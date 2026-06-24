"""Command-line argument parsing for the Blinter CLI."""

import logging
import sys
from typing import (
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)

from blinter.config.loader import create_default_config_file
from blinter.constants import MAX_LINE_LENGTH
from blinter.models import CliArguments
from blinter.output.formatters import print_help, print_version

_ArgHandlerResult = Tuple[
    None,
    Optional[bool],
    Optional[bool],
    Optional[bool],
    Optional[bool],
]


def _handle_special_cli_flags() -> Optional[bool]:
    """
    Handle special CLI flags that should exit early.

    Returns:
        None if should continue parsing, False if should exit with None
    """
    if "--version" in sys.argv:
        print_version()
        return False

    if len(sys.argv) < 2 or "--help" in sys.argv:
        print_help()
        return False

    if "--create-config" in sys.argv:
        if not create_default_config_file():
            sys.exit(1)
        return False

    return None


def _parse_max_line_length_arg(arg_index: int) -> Optional[Tuple[int, int]]:
    """
    Parse the value following ``--max-line-length``.

    Returns:
        Tuple of (next argv index, parsed line length), or None when invalid.
    """
    if arg_index + 1 >= len(sys.argv):
        print("Error: --max-line-length requires a value.\n")
        print_help()
        return None
    try:
        line_length = int(sys.argv[arg_index + 1])
        if line_length <= 0:
            print("Error: --max-line-length must be a positive integer.\n")
            return None
        if line_length > MAX_LINE_LENGTH:
            print(
                f"Error: --max-line-length must not exceed {MAX_LINE_LENGTH}.\n"
            )
            return None
        return arg_index + 1, line_length
    except ValueError:
        print(
            f"Error: --max-line-length requires a numeric value, "
            f"got '{sys.argv[arg_index + 1]}'.\n"
        )
        return None


def _parse_regular_arguments() -> Tuple[
    Optional[str],
    bool,
    Optional[bool],
    Optional[bool],
    Optional[bool],
    Optional[int],
    Optional[int],
]:
    """
    Parse regular command-line arguments using a lookup table.

    Returns:
        Tuple of (target_path, use_config, cli_show_summary, cli_recursive,
        cli_follow_calls, cli_max_line_length, cli_log_level)
    """
    positional_paths: List[str] = []
    use_config = True
    cli_show_summary: Optional[bool] = None
    cli_recursive: Optional[bool] = None
    cli_follow_calls: Optional[bool] = None
    cli_max_line_length: Optional[int] = None
    cli_verbose = False
    cli_quiet = False

    arg_handlers: Dict[str, Callable[[], _ArgHandlerResult]] = {
        "--summary": lambda: (None, None, True, None, None),
        "--severity": lambda: (None, None, None, None, None),
        "--no-recursive": lambda: (None, None, None, False, None),
        "--no-config": lambda: (None, False, None, None, None),
        "--follow-calls": lambda: (None, None, None, None, True),
    }

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if not arg.startswith("--"):
            positional_paths.append(arg)
        elif arg == "--max-line-length":
            parsed_length = _parse_max_line_length_arg(i)
            if parsed_length is None:
                sys.exit(1)
            else:
                i, cli_max_line_length = parsed_length
        elif arg == "--verbose":
            cli_verbose = True
        elif arg == "--quiet":
            cli_quiet = True
        elif arg in arg_handlers:
            _, config, summary, recursive, follow = arg_handlers[arg]()
            if config is not None:
                use_config = config
            if summary is not None:
                cli_show_summary = summary
            if recursive is not None:
                cli_recursive = recursive
            if follow is not None:
                cli_follow_calls = follow
        elif arg.startswith("--"):
            print(f"Error: Unknown option '{arg}'.\n")
            print_help()
            sys.exit(1)
        i += 1

    if cli_verbose and cli_quiet:
        print("Error: --verbose and --quiet cannot be used together.\n")
        print_help()
        sys.exit(1)

    if len(positional_paths) > 1:
        print("Error: Only one target path is allowed.\n")
        print_help()
        sys.exit(1)

    cli_log_level: Optional[int] = None
    if cli_verbose:
        cli_log_level = logging.DEBUG
    elif cli_quiet:
        cli_log_level = logging.ERROR

    target_path = positional_paths[0] if positional_paths else None

    return (
        target_path,
        use_config,
        cli_show_summary,
        cli_recursive,
        cli_follow_calls,
        cli_max_line_length,
        cli_log_level,
    )


def _parse_cli_arguments() -> Optional[CliArguments]:
    """Parse command line arguments."""
    should_continue = _handle_special_cli_flags()
    if should_continue is False:
        return None

    (
        target_path,
        use_config,
        cli_show_summary,
        cli_recursive,
        cli_follow_calls,
        cli_max_line_length,
        cli_log_level,
    ) = _parse_regular_arguments()

    if not target_path:
        print("Error: No batch file or directory provided.\n")
        print_help()
        sys.exit(1)

    return CliArguments(
        target_path,
        use_config,
        cli_show_summary,
        cli_recursive,
        cli_follow_calls,
        cli_max_line_length,
        cli_log_level,
    )
