"""Structural syntax rules driven by AST context."""

from __future__ import annotations

from typing import Dict, List

from blinter.models import LintIssue
from blinter.parsing.visitors.rule_impl.advanced.escaping import (
    _check_advanced_escaping_rules,
)
from blinter.parsing.visitors.rule_impl.syntax import (
    _check_for_do_paren_next_line,
    _check_if_block_paren_next_line,
    _check_syntax_errors,
)


def check_structure_rules(
    line: str,
    line_number: int,
    labels: Dict[str, int],
    *,
    lines: list[str],
) -> List[LintIssue]:
    """Check structural syntax for one line (AST visitor delegates here)."""
    issues = _check_syntax_errors(line, line_number, labels)
    issues.extend(_check_if_block_paren_next_line(lines, line_number))
    issues.extend(_check_for_do_paren_next_line(lines, line_number))
    issues.extend(_check_advanced_escaping_rules(line, line_number))
    return issues
