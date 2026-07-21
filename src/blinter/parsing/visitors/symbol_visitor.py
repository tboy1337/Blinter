"""Variable and symbol analysis visitors."""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from blinter.models import LintIssue
from blinter.parsing.visitors import ast_handled_rule_codes
from blinter.parsing.visitors.rule_impl.advanced.vars_syntax import (
    _check_advanced_vars,
)
from blinter.parsing.visitors.rule_impl.vars import _check_undefined_variables


def check_symbol_rules(
    lines: list[str],
    set_vars: Set[str],
    called_scripts_vars: Optional[Dict[int, Set[str]]],
    *,
    run_errors: bool,
) -> List[LintIssue]:
    """Run symbol and variable visitor checks."""
    if not run_errors:
        return []
    issues: List[LintIssue] = []
    issues.extend(_check_undefined_variables(lines, set_vars, called_scripts_vars))
    var_issues = _check_advanced_vars(lines)
    ast_codes = ast_handled_rule_codes()
    issues.extend(issue for issue in var_issues if issue.rule.code not in ast_codes)
    return issues
