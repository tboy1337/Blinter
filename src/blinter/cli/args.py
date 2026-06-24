"""Command-line argument parsing for the Blinter CLI."""

import sys
from typing import (
    Callable,
    Dict,
    Optional,
    Tuple,
)

from blinter.config.loader import create_default_config_file
from blinter.models import CliArguments
from blinter.output.formatters import print_help, print_version


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
        create_default_config_file()
        return False

    return None


def _parse_regular_arguments() -> Tuple[
    Optional[str],
    bool,
    Optional[bool],
    Optional[bool],
    Optional[bool],
    Optional[int],
]:
    """
    Parse regular command-line arguments using a lookup table.

    Returns:
        Tuple of (target_path, use_config, cli_show_summary, cli_recursive, cli_follow_calls, cli_max_line_length)
    """
    target_path: Optional[str] = None
    use_config = True
    cli_show_summary = None
    cli_recursive = None
    cli_follow_calls = None
    cli_max_line_length = None

    # Argument handlers lookup table
    arg_handlers: Dict[
        str,
        Callable[
            [],
            Tuple[None, Optional[bool], Optional[bool], Optional[bool], Optional[bool]],
        ],
    ] = {
        "--summary": lambda: (
            None,
            None,
            True,
            None,
            None,
        ),  # (path, config, summary, recursive, follow)
        "--severity": lambda: (None, None, None, None, None),
        "--no-recursive": lambda: (None, None, None, False, None),
        "--no-config": lambda: (None, False, None, None, None),
        "--follow-calls": lambda: (None, None, None, None, True),
    }

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if not arg.startswith("--"):
            if target_path is None:
                target_path = arg
        elif arg == "--max-line-length":
            # Parse the next argument as the line length value
            if i + 1 >= len(sys.argv):
                print("Error: --max-line-length requires a value.\n")
                print_help()
                sys.exit(1)
            try:
                cli_max_line_length = int(sys.argv[i + 1])
                if cli_max_line_length <= 0:
                    print("Error: --max-line-length must be a positive integer.\n")
                    sys.exit(1)
                i += 1  # Skip the next argument since we've consumed it
            except ValueError:
                print(
                    f"Error: --max-line-length requires a numeric value, got '{sys.argv[i + 1]}'.\n"
                )
                sys.exit(1)
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

    return (
        target_path,
        use_config,
        cli_show_summary,
        cli_recursive,
        cli_follow_calls,
        cli_max_line_length,
    )


def _parse_cli_arguments() -> Optional[CliArguments]:
    """Parse command line arguments."""
    # Handle special flags that exit early
    should_continue = _handle_special_cli_flags()
    if should_continue is False:
        return None

    # Parse regular arguments
    (
        target_path,
        use_config,
        cli_show_summary,
        cli_recursive,
        cli_follow_calls,
        cli_max_line_length,
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
    )
