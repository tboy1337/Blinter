"""Style and formatting line checks (S-prefix rules)."""

import re
from typing import (
    List,
    Optional,
)

from blinter.models import LintIssue
from blinter.rules.helpers import _s011_rule
from blinter.rules.registry import RULES


def _find_unquoted_separator(param_string: str) -> int:
    """
    Find the position of the first unquoted command separator (&, |).

    Args:
        param_string: The parameter string to search

    Returns:
        The position of the first unquoted separator, or the length of the string
    """
    in_quotes: bool = False
    quote_char: Optional[str] = None

    for i, char in enumerate(param_string):
        if char in ('"', "'"):
            if not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char:
                in_quotes = False
                quote_char = None
        elif not in_quotes and char in ("&", "|"):
            return i

    return len(param_string)


def _check_timeout_ping_numbers(stripped: str, line_num: int) -> List[LintIssue]:
    """
    Check for magic numbers in timeout and ping commands (S009).

    Args:
        stripped: The stripped line content
        line_num: The line number

    Returns:
        List of LintIssue objects for any magic numbers found
    """
    issues: List[LintIssue] = []
    number_patterns = [r"timeout\s+/t\s+(\d+)", r"ping\s+.*\s+-n\s+(\d+)"]

    for pattern in number_patterns:
        match = re.search(pattern, stripped, re.IGNORECASE)
        if match:
            number_result = match.group(1)
            if number_result is not None and int(number_result) > 10:
                issues.append(
                    LintIssue(
                        line_number=line_num,
                        rule=RULES["S009"],
                        context=(
                            f"Magic number '{number_result}' should be defined "
                            f"as a variable"
                        ),
                    )
                )

    return issues


def _check_style_issues(
    line: str,
    line_num: int,
    max_line_length: int = 100,
) -> List[LintIssue]:
    """Check for style level issues."""
    issues: List[LintIssue] = []
    stripped = line.strip()

    # S003: Command capitalization consistency is now checked at file level

    # S004: Trailing whitespace (strip line endings before comparing)
    line_content = line.rstrip("\r\n")
    if line_content != line_content.rstrip():
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["S004"],
                context="Line has trailing spaces or tabs",
            )
        )

    # S009: Magic numbers used (simple heuristic)
    issues.extend(_check_timeout_ping_numbers(stripped, line_num))

    # S011: Line exceeds maximum length
    line_length = len(line.rstrip("\r\n"))
    if line_length > max_line_length:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=_s011_rule(max_line_length),
                context=f"Line is {line_length} characters (max {max_line_length})",
            )
        )

    # S014: Long parameter list affects readability
    call_match = re.match(r"call\s+:[A-Z0-9_]+\s+(.*)", stripped, re.IGNORECASE)
    if call_match:
        param_string: str = call_match.group(1)
        separator_pos: int = _find_unquoted_separator(param_string)
        param_string_before_chain: str = param_string[:separator_pos].strip()
        params: list[str] = (
            param_string_before_chain.split() if param_string_before_chain else []
        )

        if len(params) > 5:  # More than 5 parameters
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["S014"],
                    context=f"Function call has {len(params)} parameters, consider grouping them",
                )
            )

    return issues
