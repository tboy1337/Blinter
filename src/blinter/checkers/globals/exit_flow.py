"""Exit statements and unreachable-code detection."""

import re
from typing import (
    Dict,
    List,
    Optional,
    Set,
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
    can_reach_eof = _can_execution_reach_eof(lines)

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


def _has_executable_after(lines: List[str], start_index: int) -> bool:
    """Return True when executable commands appear after start_index."""
    for line in lines[start_index + 1 :]:
        if _is_truly_executable_command(line.strip().lower()):
            return True
    return False


def _is_else_transition(stripped: str) -> bool:
    """Return True when a line closes a block and opens an ELSE branch."""
    close_match = re.match(r"^\)(?:\s*(?:>>|[12]>|[<>]))?", stripped)
    if not close_match:
        return False
    remainder = stripped[close_match.end() :].strip()
    return bool(re.match(r"else\b", remainder, re.IGNORECASE))


def _if_else_block_exits_reach_eof(
    previous_depth: int,
    paren_depth: int,
    branch_state: tuple[bool, bool],
    lines: List[str],
    index: int,
) -> bool:
    """Return True when a completed IF/ELSE always exits and has no code after."""
    if_branch_exited, else_branch_exited = branch_state
    return (
        previous_depth == 1
        and paren_depth == 0
        and if_branch_exited
        and else_branch_exited
        and not _has_executable_after(lines, index)
    )


def _build_label_index(lines: List[str]) -> Dict[str, int]:
    """Map normalized label names to zero-based line indices."""
    labels: Dict[str, int] = {}
    for index, line in enumerate(lines):
        stripped = line.strip().lower()
        if not stripped.startswith(":") or stripped.startswith("::"):
            continue
        label_content = stripped[1:]
        if re.search(r"[a-zA-Z0-9]", label_content):
            labels[stripped] = index
    return labels


def _normalize_goto_target(target: str) -> str:
    """Normalize a GOTO target to lowercase label form ``:name``."""
    normalized = target.lower().strip()
    if not normalized.startswith(":"):
        normalized = f":{normalized}"
    return normalized


def _parse_goto_target(stripped: str) -> Optional[str]:
    """Extract and normalize the label target from a GOTO line."""
    match = re.match(r"goto\s+(\S+)", stripped, re.IGNORECASE)
    if match is None:
        return None
    return _normalize_goto_target(match.group(1))


def _is_goto_eof_target(target: str) -> bool:
    """Return True when GOTO targets the implicit end-of-file label."""
    return target.lstrip(":") == "eof"


def _can_main_execution_reach_eof(lines: List[str]) -> bool:
    """Determine if the main execution path can reach EOF without EXIT."""
    return _can_execution_reach_eof(lines)


def _can_execution_reach_eof(  # pylint: disable=too-many-branches,too-many-return-statements
    lines: List[str],
    start_index: int = 0,
    visiting_labels: Optional[Set[str]] = None,
) -> bool:
    """Determine if execution from start_index can reach EOF without EXIT.

    This performs a forward scan through the script tracking whether we can
    reach EOF. It considers:
    - EXIT statements (blocks path to EOF)
    - GOTO statements (follows label targets when resolvable)
    - Labels (can be jumped to)
    - Conditional blocks (IF/FOR with parentheses)
    """
    if visiting_labels is None:
        visiting_labels = set()

    labels = _build_label_index(lines)
    reachable = True
    paren_depth = 0
    if_branch_exited = False
    else_branch_exited = False
    in_else_branch = False

    for index in range(start_index, len(lines)):
        stripped = lines[index].strip().lower()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("rem") or stripped.startswith("::"):
            continue

        # Labels make code reachable again
        if stripped.startswith(":") and not stripped.startswith("::"):
            reachable = True
            continue

        previous_depth = paren_depth
        paren_depth = _update_paren_depth(stripped, paren_depth)
        if paren_depth > previous_depth and re.search(
            r"\bif\b", stripped, re.IGNORECASE
        ):
            if_branch_exited = False
            else_branch_exited = False
            in_else_branch = False
        elif _is_else_transition(stripped):
            in_else_branch = True

        if re.match(r"exit\b", stripped):
            if paren_depth == 0:
                return False
            if in_else_branch:
                else_branch_exited = True
            else:
                if_branch_exited = True
        elif _if_else_block_exits_reach_eof(
            previous_depth,
            paren_depth,
            (if_branch_exited, else_branch_exited),
            lines,
            index,
        ):
            return False
        elif paren_depth == 0 and re.match(r"goto\s+", stripped):
            target = _parse_goto_target(stripped)
            if target is None or _is_goto_eof_target(target):
                return False
            if target in visiting_labels:
                return False
            label_index = labels.get(target)
            if label_index is None:
                return False
            visiting_labels.add(target)
            return _can_execution_reach_eof(
                lines,
                start_index=label_index,
                visiting_labels=visiting_labels,
            )

    return reachable


def _check_nested_paren_mismatch(lines: List[str]) -> List[LintIssue]:
    """Check for mismatched IF/FOR parenthesis blocks (E001)."""
    issues: List[LintIssue] = []
    depth = 0
    last_open_line = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith("rem") or stripped.startswith("::"):
            continue

        previous_depth = depth
        depth = _update_paren_depth(stripped, depth)
        if depth > previous_depth:
            last_open_line = i

        if depth < 0:
            issues.append(
                LintIssue(
                    line_number=i,
                    rule=RULES["E001"],
                    context="Unmatched closing parenthesis in IF/FOR block",
                )
            )
            depth = 0

    if depth > 0:
        issues.append(
            LintIssue(
                line_number=last_open_line or len(lines),
                rule=RULES["E001"],
                context=f"{depth} unclosed parenthesis block(s) in IF/FOR structure",
            )
        )

    return issues


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


_BLOCK_CLOSE_PATTERN = re.compile(
    r"^\)(?:\s*(?:"
    r">>?\s*(?:\"[^\"]*\"|\S+)?|"
    r"[12]>&?[12]?|"
    r">\s*(?:\"[^\"]*\"|\S+)"
    r"))?",
    re.IGNORECASE,
)


def _is_bare_paren_block_open(line: str) -> bool:
    """Return True for ``( command `` groups that are not IF/FOR headers."""
    if not re.match(r"^\(", line):
        return False
    return re.search(r"\b(?:if|for)\b", line, re.IGNORECASE) is None


def _line_opens_block_depth(line: str) -> int:
    """Return how many IF/FOR/(group) blocks open on this line."""
    if _is_bare_paren_block_open(line):
        return 1
    if re.search(r"\bfor\b", line, re.IGNORECASE) and (
        re.search(r"\bdo\s*\(\s*$", line, re.IGNORECASE)
        or re.search(r"\bfor\b.*\(", line, re.IGNORECASE)
    ):
        return 1
    if re.search(r"\bif\b", line, re.IGNORECASE) and re.search(r"\(\s*$", line):
        return 1
    return 0


def _update_paren_depth(line: str, current_depth: int) -> int:
    """Update parentheses depth based on the line content."""
    close_match = _BLOCK_CLOSE_PATTERN.match(line)
    if close_match:
        current_depth -= 1
        remainder = line[close_match.end() :].strip()
        if re.match(r"else\b", remainder, re.IGNORECASE) and re.search(
            r"\(", remainder
        ):
            current_depth += 1
        return current_depth

    return current_depth + _line_opens_block_depth(line)


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
