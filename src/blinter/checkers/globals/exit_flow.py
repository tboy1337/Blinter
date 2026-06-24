"""Exit statements and unreachable-code detection."""

import re
from typing import (
    List,
    Optional,
)

from blinter.models import LintIssue
from blinter.rules.registry import RULES


def _check_missing_exit_statement(  # pylint: disable=too-many-branches
    lines: List[str],
) -> List[LintIssue]:
    """Check if script can reach EOF without an explicit EXIT statement (W001).

    This function performs control flow analysis to determine if the main execution
    path can fall through to end-of-file without encountering an EXIT statement.

    Smart detection includes:
    - Allows scripts where all paths lead to EXIT or GOTO :EOF
    - Allows pure subroutine libraries (scripts that start with a label before any executable code)
    - Allows scripts with only @echo off and comments (essentially setup-only scripts)
    - Flags scripts where main execution can fall through to EOF
    - Understands GOTO, labels, and conditional branches
    """
    issues: List[LintIssue] = []

    # Empty script or comments-only script doesn't need exit
    has_meaningful_code = False
    first_executable_line = -1
    first_label_line = -1

    # Find first executable code and first label
    for i, line in enumerate(lines):
        stripped = line.strip().lower()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("rem") or stripped.startswith("::"):
            continue

        # Check for labels (but not comment-style labels)
        if stripped.startswith(":") and not stripped.startswith("::"):
            if first_label_line == -1:
                first_label_line = i
            continue

        # Check for executable code
        if _is_truly_executable_command(stripped):
            if first_executable_line == -1:
                first_executable_line = i
            # @echo off is a setup command, not meaningful executable code
            # Only count as meaningful if it's not just @echo off/on
            if not re.match(r"^@?echo\s+(off|on)$", stripped):
                has_meaningful_code = True

    # If no meaningful executable code, no issue
    if not has_meaningful_code:
        return issues

    # If first label comes before first executable code, this is a subroutine library
    # These scripts are meant to be CALLed, not executed directly
    if (
        first_label_line != -1
        and first_executable_line != -1
        and first_label_line < first_executable_line
    ):
        return issues

    # Now check if the main execution path reaches EOF without EXIT
    # Scan backwards from end of file to find if we can reach EOF
    can_reach_eof = _can_main_execution_reach_eof(lines)

    if can_reach_eof:
        # Find the last line of executable code to report the issue there
        last_executable_line = -1
        for i in range(len(lines) - 1, -1, -1):
            stripped = lines[i].strip().lower()
            if _is_truly_executable_command(stripped):
                last_executable_line = i + 1  # Convert to 1-indexed
                break

        if last_executable_line > 0:
            issues.append(
                LintIssue(
                    line_number=last_executable_line,
                    rule=RULES["W001"],
                    context="Script can reach end of file without explicit EXIT statement",
                )
            )

    return issues


def _can_main_execution_reach_eof(lines: List[str]) -> bool:
    """Determine if the main execution path can reach end-of-file without EXIT.

    This performs a forward scan through the script tracking whether we can
    reach EOF. It considers:
    - EXIT statements (blocks path to EOF)
    - GOTO statements (may redirect control flow)
    - Labels (can be jumped to)
    - Conditional blocks (IF/FOR with parentheses)
    """
    # Track whether we're in reachable code
    reachable = True
    paren_depth = 0

    for line in lines:
        stripped = line.strip().lower()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("rem") or stripped.startswith("::"):
            continue

        # Labels make code reachable again
        if stripped.startswith(":") and not stripped.startswith("::"):
            reachable = True
            continue

        # Update parentheses depth for IF/FOR blocks
        paren_depth = _update_paren_depth(stripped, paren_depth)

        # Check for EXIT statements
        if re.match(r"exit\b", stripped):
            # EXIT makes code unreachable
            # But only if we're at the top level (not inside IF/FOR blocks)
            if paren_depth == 0:
                reachable = False
                continue

        # Check for unconditional GOTO (not inside IF statement)
        # GOTO at top level redirects control flow
        if paren_depth == 0 and re.match(r"goto\s+", stripped):
            # Check if it's GOTO :EOF (which is like EXIT)
            if re.match(r"goto\s+:eof\b", stripped):
                reachable = False
                continue
            # Other GOTO statements redirect flow, making subsequent code unreachable
            # until we hit a label
            reachable = False
            continue

    # If we finished the scan and code is still reachable, we can reach EOF
    return reachable


def _check_unreachable_code(lines: List[str]) -> List[LintIssue]:
    """Check for unreachable code after EXIT or GOTO statements."""
    issues: List[LintIssue] = []

    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        if re.match(r"(exit\s|goto\s)", stripped):
            # Find unreachable code after this EXIT/GOTO
            unreachable_line = _find_truly_unreachable_code(lines, i)
            if unreachable_line is not None:
                command = stripped.split()[0].upper()
                issues.append(
                    LintIssue(
                        line_number=unreachable_line + 1,
                        rule=RULES["E008"],
                        context=(
                            f"Code after {command} on line {i + 1} will never execute"
                        ),
                    )
                )

    return issues


def _find_truly_unreachable_code(
    lines: List[str], exit_line_index: int
) -> Optional[int]:
    """Find truly unreachable code, considering batch file control flow properly."""
    exit_paren_depth = _calculate_exit_paren_depth(lines, exit_line_index)
    return _scan_for_unreachable_code(lines, exit_line_index, exit_paren_depth)


def _calculate_exit_paren_depth(lines: List[str], exit_line_index: int) -> int:
    """Calculate the parentheses depth at the EXIT statement."""
    current_paren_depth = 0

    for i in range(exit_line_index + 1):
        line = lines[i].strip().lower()
        current_paren_depth = _update_paren_depth(line, current_paren_depth)

    return current_paren_depth


def _scan_for_unreachable_code(
    lines: List[str], exit_line_index: int, exit_paren_depth: int
) -> Optional[int]:
    """Scan forward from EXIT to find unreachable code."""
    current_paren_depth = exit_paren_depth

    for j in range(exit_line_index + 1, len(lines)):
        line = lines[j].strip().lower()

        # Skip empty lines and comments
        if not line or line.startswith("rem") or line.startswith("::"):
            continue

        # Check if this line makes code reachable again
        if _line_makes_code_reachable(line):
            return None

        # Update parentheses depth
        current_paren_depth = _update_paren_depth(line, current_paren_depth)

        # Handle closing parentheses specially
        if line == ")":
            if current_paren_depth < exit_paren_depth:
                return None
            continue

        # Skip certain structural elements
        if line in {"endlocal", "setlocal"}:
            continue

        # Check for executable code
        if _is_truly_executable_command(line):
            if exit_paren_depth == 0 or current_paren_depth >= exit_paren_depth:
                return j
            return None

    return None


def _update_paren_depth(line: str, current_depth: int) -> int:
    """Update parentheses depth based on the line content."""
    # Match IF or FOR statements with opening parentheses
    if re.search(r"\b(?:if|for)\b.*\(", line):
        return current_depth + 1
    # Match closing parenthesis even with redirect operators
    # Examples: ), ) >>file.txt, ) 2>&1, ) >>file.log 2>&1, ) >nul 2>&1
    # Pattern: ) followed by optional whitespace and optional redirects
    # Order matters: >> must be checked before > to avoid partial match
    if re.match(r"^\)(?:\s*(?:>>|[12]>|[<>]))?", line):
        return current_depth - 1
    return current_depth


def _line_makes_code_reachable(line: str) -> bool:
    """Check if a line makes code reachable again."""
    # Labels make code reachable
    if line.startswith(":") and not line.startswith("::"):
        return True

    # ') else' creates a new reachable path
    if re.match(r"^\)\s*else\b", line):
        return True

    return False


def _is_truly_executable_command(line: str) -> bool:
    """Check if a line is truly executable code (not structural)."""
    line = line.strip().lower()

    # Skip empty, comments, labels
    if (
        not line
        or line.startswith("rem")
        or line.startswith("::")
        or line.startswith(":")
    ):
        return False

    # Skip pure structural elements
    if line in {")", "endlocal", "setlocal"}:
        return False

    # Skip ') else' patterns
    if re.match(r"^\)\s*(else\b.*)?$", line):
        return False

    # Skip closing parenthesis with redirection operators
    # These are part of block I/O redirection, not executable code
    # Examples: ) >>file.txt 2>&1, ) >output.log, ) 2>nul
    if re.match(r"^\)\s*(?:>>?|<|[12]>&?[12]?)", line):
        return False

    return True
