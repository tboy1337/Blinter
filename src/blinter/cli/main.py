"""CLI entry point and multi-file batch processing orchestration."""

from pathlib import Path
import sys
from typing import (
    Dict,
    List,
    NoReturn,
    Optional,
    Set,
    Tuple,
)
from blinter._version import __version__
from blinter.cli.args import _parse_cli_arguments
from blinter.config.loader import load_config
from blinter.engine.dependencies import (
    _build_call_dependency_graph,
    _extract_called_scripts,
)
from blinter.engine.linter import lint_batch_file
from blinter.io.discovery import find_batch_files
from blinter.models import (
    BlinterConfig,
    LintIssue,
    ProcessingResults,
    ProcessingState,
    RuleSeverity,
)
from blinter.output.formatters import (
    print_detailed,
    print_severity_info,
    print_summary,
)

def _cli_error(message: str) -> NoReturn:
    """Print an error message and exit with status code 1."""
    print(message)
    raise SystemExit(1)

def _process_single_called_script(
    called_script: Path,
    config: BlinterConfig,
    processed_files: Set[Path],
    all_issues: List[LintIssue],
    file_results: Dict[str, List[LintIssue]],
) -> Tuple[int, int, Optional[str]]:
    """
    Process a single called script.

    Returns:
        Tuple of (files_processed, files_with_errors, processed_path)
        processed_path is None if the file was not processed
    """
    # Skip if already processed
    if called_script.resolve() in processed_files:
        return (0, 0, None)

    try:
        called_issues = lint_batch_file(str(called_script), config=config)
        file_results[str(called_script)] = called_issues
        all_issues.extend(called_issues)
        processed_files.add(called_script.resolve())

        has_errors = any(
            issue.rule.severity == RuleSeverity.ERROR for issue in called_issues
        )
        return (1, 1 if has_errors else 0, str(called_script))

    except (
        UnicodeDecodeError,
        FileNotFoundError,
        PermissionError,
        OSError,
        ValueError,
        TypeError,
    ) as called_error:
        error_msg = (
            f"Warning: Could not process called script "
            f"'{called_script}': {called_error}"
        )
        print(error_msg)
        return (0, 0, None)

def _process_called_scripts(
    batch_file: Path,
    config: BlinterConfig,
    state: ProcessingState,
) -> Tuple[int, int]:
    """
    Process all called scripts for a batch file.

    Args:
        batch_file: The batch file to extract called scripts from
        config: Configuration settings
        state: Processing state container

    Returns:
        Tuple of (files_processed, files_with_errors)
    """
    files_processed = 0
    files_with_errors = 0
    called_scripts = _extract_called_scripts(batch_file)

    for called_script in called_scripts:
        result = _process_single_called_script(
            called_script,
            config,
            state.processed_files,
            state.all_issues,
            state.file_results,
        )
        files_processed += result[0]
        files_with_errors += result[1]
        if result[2]:  # called_path
            state.processed_file_paths.append((result[2], str(batch_file)))

    return files_processed, files_with_errors

def _process_batch_files(
    batch_files: List[Path], config: BlinterConfig
) -> Optional[ProcessingResults]:
    """Process all batch files and collect results."""
    state = ProcessingState(
        processed_files=set(), all_issues=[], file_results={}, processed_file_paths=[]
    )
    total_files_processed = 0
    files_with_errors = 0

    # Build dependency graph if follow_calls is enabled
    dependency_graph: Optional[Dict[Path, Set[Path]]] = None
    if config.follow_calls:
        dependency_graph = _build_call_dependency_graph(batch_files)

    for batch_file in batch_files:
        # Skip if already processed (could happen with follow_calls)
        if batch_file.resolve() in state.processed_files:
            continue

        try:
            issues = lint_batch_file(
                str(batch_file), config=config, dependency_graph=dependency_graph
            )
            state.file_results[str(batch_file)] = issues
            state.all_issues.extend(issues)
            total_files_processed += 1
            state.processed_files.add(batch_file.resolve())
            state.processed_file_paths.append(
                (str(batch_file), None)
            )  # Main file, no parent

            if any(issue.rule.severity == RuleSeverity.ERROR for issue in issues):
                files_with_errors += 1

            # If follow_calls is enabled, process called scripts
            if config.follow_calls:
                called_results = _process_called_scripts(batch_file, config, state)
                total_files_processed += called_results[0]
                files_with_errors += called_results[1]

        except UnicodeDecodeError as decode_error:
            print(
                f"Warning: Could not read '{batch_file}' due to encoding issues: {decode_error}"
            )
            continue
        except (
            FileNotFoundError,
            PermissionError,
            OSError,
            ValueError,
            TypeError,
        ) as file_error:
            print(f"Warning: Could not process '{batch_file}': {file_error}")
            continue

    if total_files_processed == 0:
        print("Error: No batch files could be processed.")
        return None

    return ProcessingResults(
        state.all_issues,
        state.file_results,
        total_files_processed,
        files_with_errors,
        state.processed_file_paths,
    )

def _display_analyzed_scripts(
    processed_file_paths: List[Tuple[str, Optional[str]]],
    target_path: str,
    is_directory: bool,
) -> None:
    """
    Display the list of analyzed scripts.

    Args:
        processed_file_paths: List of (file_path, called_by_parent) tuples
        target_path: The original target path provided by user
        is_directory: Whether the target was a directory
    """
    if not processed_file_paths:
        return

    print("Scripts Analyzed:")
    for idx, (file_path, parent) in enumerate(processed_file_paths, 1):
        # Format the file path
        display_path: str
        if is_directory:
            try:
                display_path = str(Path(file_path).relative_to(Path(target_path)))
            except ValueError:
                # If relative_to fails (file outside target), use absolute path
                display_path = str(Path(file_path))
        else:
            display_path = Path(file_path).name

        # Display with parent information if it's a called script
        if parent:
            parent_name = Path(parent).name
            print(f"  {idx}.   ↳ {display_path} (called by {parent_name})")
        else:
            print(f"  {idx}. {display_path}")

    print()

def _display_results(
    results: ProcessingResults,
    target_path: str,
    config: BlinterConfig,
) -> None:
    """Display lint results to the user."""
    is_directory = Path(target_path).is_dir()

    if is_directory:
        print(f"\n Batch Files Analysis: {target_path}")
        print("=" * (26 + len(target_path)))
        file_count_text = "s" if results.total_files_processed != 1 else ""
        print(f"Processed {results.total_files_processed} batch file{file_count_text}")
        print()

        # Show list of analyzed scripts
        _display_analyzed_scripts(
            results.processed_file_paths, target_path, is_directory
        )

        # Show results for each file if there are multiple files
        if len(results.file_results) > 1:
            for file_path, issues in results.file_results.items():
                relative_path = Path(file_path).relative_to(Path(target_path))
                print(f"\n File: {relative_path}")
                print("-" * (8 + len(str(relative_path))))

                if issues:
                    print_detailed(issues)
                else:
                    print("No issues found! OK")
                print()
        else:
            # Single file in directory
            print_detailed(results.all_issues)
    else:
        # Single file processing
        print(f"\n Batch File Analysis: {target_path}")
        print("=" * (25 + len(target_path)))

        # Show list of analyzed scripts
        _display_analyzed_scripts(
            results.processed_file_paths, target_path, is_directory
        )

        print_detailed(results.all_issues)

    # Show combined summary if processing multiple files
    if is_directory and len(results.file_results) > 1:
        print("\n COMBINED RESULTS:")
        print("===================")

    if config.show_summary:
        print_summary(results.all_issues)

    print_severity_info(results.all_issues)

def _exit_with_results(results: ProcessingResults, target_path: str) -> None:
    """Exit with appropriate code based on results."""
    is_directory = Path(target_path).is_dir()
    error_count = sum(
        1 for issue in results.all_issues if issue.rule.severity == RuleSeverity.ERROR
    )

    if is_directory:
        if error_count > 0:
            error_text = "s" if error_count != 1 else ""
            file_text = "s" if results.files_with_errors != 1 else ""
            print(
                f"\nWARNING  Found {error_count} critical error{error_text} "
                f"across {results.files_with_errors} file{file_text} that must be fixed."
            )
            sys.exit(1)
        elif results.all_issues:
            issue_text = "s" if len(results.all_issues) != 1 else ""
            file_text = "s" if results.total_files_processed != 1 else ""
            print(
                f"\nOK No critical errors found, but {len(results.all_issues)} "
                f"total issue{issue_text} detected across "
                f"{results.total_files_processed} file{file_text}."
            )
            sys.exit(0)
        else:
            file_text = "s" if results.total_files_processed != 1 else ""
            look_text = "s" if results.total_files_processed == 1 else ""
            print(
                f"\n* No issues found! All {results.total_files_processed} "
                f"batch file{file_text} look{look_text} great!"
            )
            sys.exit(0)
    else:
        if error_count > 0:
            print(
                f"\nWARNING  Found {error_count} critical "
                f"error{'s' if error_count != 1 else ''} that must be fixed."
            )
            sys.exit(1)
        elif results.all_issues:
            print(
                f"\nOK No critical errors found, but {len(results.all_issues)} "
                f"issue{'s' if len(results.all_issues) != 1 else ''} detected."
            )
            sys.exit(0)
        else:
            print("\nNo issues found! Your batch file looks great!")
            sys.exit(0)

def main() -> None:
    """Main entry point for the blinter application."""
    # Configure stdout for UTF-8 encoding to handle Unicode characters on Windows
    # This prevents UnicodeEncodeError when outputting to cp1252 console
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError):
        # Fallback for older Python versions or when reconfigure is not available
        pass

    # Parse CLI arguments
    cli_args = _parse_cli_arguments()
    if cli_args is None:
        return

    # Display version information
    print(f"Blinter v{__version__} - Batch File Linter\n")

    # Load configuration
    config = load_config(use_config=cli_args.use_config)

    # Override config with CLI arguments
    if cli_args.cli_show_summary is not None:
        config.show_summary = cli_args.cli_show_summary
    if cli_args.cli_recursive is not None:
        config.recursive = cli_args.cli_recursive
    if cli_args.cli_follow_calls is not None:
        config.follow_calls = cli_args.cli_follow_calls
    if cli_args.cli_max_line_length is not None:
        config.max_line_length = cli_args.cli_max_line_length

    # Find all batch files to process
    try:
        batch_files = find_batch_files(
            cli_args.target_path, recursive=config.recursive
        )
    except FileNotFoundError:
        _cli_error(f"Error: Path '{cli_args.target_path}' not found.")
    except ValueError as value_error:
        _cli_error(f"Error: {value_error}")
    except (OSError, PermissionError) as path_error:
        _cli_error(f"Error: Cannot access '{cli_args.target_path}': {path_error}")

    if not batch_files:
        _cli_error(f"No batch files (.bat or .cmd) found in: {cli_args.target_path}")

    # Process batch files
    results = _process_batch_files(batch_files, config)
    if results is None:
        sys.exit(1)

    # Display results
    _display_results(results, cli_args.target_path, config)

    # Exit with appropriate code
    _exit_with_results(results, cli_args.target_path)
