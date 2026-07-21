"""SETLOCAL and delayed-expansion visitor checks."""

from __future__ import annotations

from typing import List

from blinter.models import LintIssue
from blinter.parsing.visitors.rule_impl.performance import (
    _check_setlocal_nesting_depth,
)


def check_setlocal_rules(
    lines: list[str],
    *,
    run_performance: bool,
    run_warnings: bool,
) -> List[LintIssue]:
    """Run SETLOCAL nesting and related visitor checks."""
    del run_warnings
    if not run_performance:
        return []
    return list(_check_setlocal_nesting_depth(lines))
