"""Encoding and line-ending rules (pre-parse byte analysis)."""

from __future__ import annotations

from typing import List, Optional

from blinter.io.encoding import LineEndingInfo
from blinter.models import LintIssue
from blinter.parsing.visitors.rule_impl.globals.analysis import (
    _check_global_style_rules,
)
from blinter.parsing.visitors.rule_impl.line_endings import _check_line_ending_rules


def check_encoding_rules(
    lines: list[str],
    file_path: str,
    *,
    ending_info: Optional[LineEndingInfo] = None,
    run_style: bool,
    run_warnings: bool,
    run_errors: bool,
) -> List[LintIssue]:
    """Run encoding and line-ending visitor checks."""
    issues: List[LintIssue] = []
    if run_errors or run_warnings or run_style:
        issues.extend(
            _check_line_ending_rules(lines, file_path, ending_info=ending_info)
        )
    if run_style:
        issues.extend(_check_global_style_rules(lines, file_path))
    return issues
