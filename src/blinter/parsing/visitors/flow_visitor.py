"""Control-flow and global script analysis visitors."""

from __future__ import annotations

from typing import List

from blinter.constants import LARGE_FILE_LINE_THRESHOLD
from blinter.models import BlinterConfig, LintIssue
from blinter.parsing.visitors.rule_impl.advanced.enhanced import (
    _check_enhanced_commands,
)
from blinter.parsing.visitors.rule_impl.advanced.style_security_perf import (
    _check_advanced_style_rules,
    _check_enhanced_performance,
    _check_enhanced_security_rules,
)
from blinter.parsing.visitors.rule_impl.globals.analysis import (
    _check_new_global_rules,
)
from blinter.parsing.visitors.rule_impl.globals.exit_flow import (
    _check_missing_exit_statement,
    _check_nested_paren_mismatch,
    _check_unreachable_code,
)
from blinter.parsing.visitors.rule_impl.globals.style_globals import (
    _check_cmd_case_consistency,
    _check_code_duplication,
    _check_inconsistent_indentation,
    _check_missing_header_doc,
    _check_missing_pause,
    _check_redundant_operations,
)


def check_flow_rules(
    lines: list[str],
    *,
    run_errors: bool,
    run_warnings: bool,
    run_style: bool,
    run_security: bool,
    run_performance: bool,
    config: BlinterConfig,
    file_path: str = "",
) -> List[LintIssue]:
    """Run flow and global visitor checks across the script."""
    issues: List[LintIssue] = []
    if run_errors:
        issues.extend(_check_nested_paren_mismatch(lines))

    if run_warnings:
        issues.extend(_check_missing_exit_statement(lines))
        if len(lines) <= LARGE_FILE_LINE_THRESHOLD:
            issues.extend(_check_unreachable_code(lines))
        issues.extend(_check_code_duplication(lines))
        issues.extend(_check_enhanced_commands(lines))
        issues.extend(_check_missing_pause(lines))

    if run_security:
        issues.extend(_check_enhanced_security_rules(lines))

    if run_performance:
        issues.extend(_check_redundant_operations(lines))
        issues.extend(_check_enhanced_performance(lines))

    if run_style:
        issues.extend(_check_inconsistent_indentation(lines))
        issues.extend(_check_missing_header_doc(lines))
        if len(lines) <= LARGE_FILE_LINE_THRESHOLD:
            issues.extend(_check_cmd_case_consistency(lines))
        issues.extend(_check_advanced_style_rules(lines, config.max_line_length))

    if file_path:
        issues.extend(_check_new_global_rules(lines, file_path))

    return issues
