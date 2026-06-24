"""Blinter package module."""

import re
from typing import (
    List,
    Tuple,
)
from blinter.io.encoding import _has_multibyte_chars
from blinter.logging_config import logger
from blinter.models import LintIssue
from blinter.rules.registry import RULES
from blinter.io.encoding import _detect_line_endings

def _check_line_ending_rules(lines: List[str], file_path: str) -> List[LintIssue]:
    """
    Check for line ending related issues (E018, S005, W018, W019, S016).

    This function implements the critical line ending checks based on Windows batch
    parser limitations and the Stack Overflow findings about Unix line ending bugs.

    Args:
        lines: List of file lines (already processed by Python's universal newlines)
        file_path: Path to the file being analyzed

    Returns:
        List of LintIssue objects for line ending related problems
    """
    if not lines:
        return []

    try:
        return _analyze_line_endings(lines, file_path)
    except OSError as line_ending_error:
        logger.warning(
            "Could not analyze line endings for %s: %s", file_path, line_ending_error
        )
        return []

def _analyze_line_endings(lines: List[str], file_path: str) -> List[LintIssue]:
    """Analyze line endings and return related issues."""
    issues: List[LintIssue] = []
    ending_info = _detect_line_endings(file_path)
    ending_type = ending_info[0]

    # Check basic line ending issues
    issues.extend(_check_basic_line_ending_issues(ending_info))

    # Check for risks with non-CRLF endings
    if ending_type in ["LF", "CR", "MIXED"]:
        issues.extend(_check_multibyte_risks(lines, ending_type))
        issues.extend(_check_goto_call_risks(lines, ending_type))
        issues.extend(_check_doublecolon_risks(lines, ending_type))

    return issues

def _check_basic_line_ending_issues(
    ending_info: Tuple[str, bool, int, int, int],
) -> List[LintIssue]:
    """Check for E018 and S005 line ending issues."""
    ending_type, has_mixed, crlf_count, lf_only_count, cr_only_count = ending_info
    issues: List[LintIssue] = []

    if ending_type == "LF":
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["E018"],
                context=(
                    f"File uses Unix line endings (LF-only) - "
                    f"{lf_only_count} LF sequences found"
                ),
            )
        )
    elif has_mixed and ending_type == "MIXED":
        issues.append(
            LintIssue(
                line_number=1,
                rule=RULES["S005"],
                context=(
                    f"File has mixed line endings - CRLF: {crlf_count}, "
                    f"LF-only: {lf_only_count}, CR-only: {cr_only_count}"
                ),
            )
        )

    return issues

def _check_multibyte_risks(lines: List[str], ending_type: str) -> List[LintIssue]:
    """Check for W018 multi-byte character risks."""
    has_multibyte, affected_lines = _has_multibyte_chars(lines)
    if has_multibyte:
        return [
            LintIssue(
                line_number=affected_lines[0],
                rule=RULES["W018"],
                context=(
                    f"Multi-byte characters found on lines {affected_lines} "
                    f"with {ending_type} line endings"
                ),
            )
        ]
    return []

def _check_goto_call_risks(lines: List[str], ending_type: str) -> List[LintIssue]:
    """Check for W019 GOTO/CALL risks."""
    goto_call_lines = [
        line_num
        for line_num, line in enumerate(lines, start=1)
        if re.match(r"(goto|call)\s+:", line.strip().lower())
    ]

    if goto_call_lines:
        return [
            LintIssue(
                line_number=goto_call_lines[0],
                rule=RULES["W019"],
                context=(
                    f"GOTO/CALL statements found on lines {goto_call_lines[:5]} "
                    f"with {ending_type} line endings"
                ),
            )
        ]
    return []

def _check_doublecolon_risks(lines: List[str], ending_type: str) -> List[LintIssue]:
    """Check for S016 double-colon comment risks."""
    doublecolon_lines = [
        line_num
        for line_num, line in enumerate(lines, start=1)
        if line.strip().startswith("::")
    ]

    if doublecolon_lines:
        return [
            LintIssue(
                line_number=doublecolon_lines[0],
                rule=RULES["S016"],
                context=(
                    f"Double-colon comments found on lines {doublecolon_lines[:5]} "
                    f"with {ending_type} line endings"
                ),
            )
        ]
    return []
