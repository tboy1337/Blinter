"""Heuristic visitors for warnings, security, performance, and style."""

from __future__ import annotations

from typing import Dict, List

from blinter.constants import LARGE_FILE_LINE_THRESHOLD
from blinter.models import LintIssue
from blinter.parsing.visitors.rule_impl.advanced import (
    _check_advanced_for_rules,
    _check_advanced_performance,
    _check_advanced_process_mgmt,
    _check_advanced_security,
    _check_advanced_style_patterns,
)
from blinter.parsing.visitors.rule_impl.performance import _check_performance_issues
from blinter.parsing.visitors.rule_impl.security import _check_security_issues
from blinter.parsing.visitors.rule_impl.style import _check_style_issues
from blinter.parsing.visitors.rule_impl.warnings import _check_warning_issues


def check_warning_rules(
    line: str,
    line_number: int,
    set_vars: set[str],
    has_delayed_expansion: bool,
    *,
    lines: list[str],
) -> List[LintIssue]:
    """Run warning heuristic visitor for one line."""
    issues = _check_warning_issues(
        line,
        line_number,
        set_vars,
        has_delayed_expansion,
        lines=lines,
    )
    issues.extend(_check_advanced_for_rules(line, line_number, lines=lines))
    issues.extend(_check_advanced_process_mgmt(line, line_number))
    return issues


def check_style_rules(
    line: str,
    line_number: int,
    lines: list[str],
    max_line_length: int,
) -> List[LintIssue]:
    """Run style heuristic visitor for one line."""
    issues = _check_style_issues(line, line_number, max_line_length)
    issues.extend(_check_advanced_style_patterns(line, line_number, lines))
    return issues


def check_security_rules(
    line: str,
    line_number: int,
    lines: list[str],
    labels: Dict[str, int],
) -> List[LintIssue]:
    """Run security heuristic visitor for one line."""
    issues = _check_security_issues(line, line_number, lines)
    issues.extend(_check_advanced_security(line, line_number, lines, labels))
    return issues


def check_performance_rules(
    lines: list[str],
    line_number: int,
    line: str,
    has_setlocal: bool,
    has_set_commands: bool,
    has_delayed_expansion: bool,
    uses_delayed_vars: bool,
    has_disable_delayed_expansion: bool,
    has_literal_exclamations: bool,
    has_disable_expansion_lines: bool,
) -> List[LintIssue]:
    """Run performance heuristic visitor for one line."""
    issues = _check_performance_issues(
        lines,
        line_number,
        line,
        has_setlocal,
        has_set_commands,
        has_delayed_expansion,
        uses_delayed_vars,
        has_disable_delayed_expansion,
        has_literal_exclamations,
        has_disable_expansion_lines,
    )
    if len(lines) <= LARGE_FILE_LINE_THRESHOLD:
        issues.extend(_check_advanced_performance(lines, line_number, line))
    return issues
