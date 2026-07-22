"""Unified AST-first lint pipeline orchestrating all visitor passes."""

from typing import Dict, List, Optional, Set

from blinter.constants import LARGE_FILE_LINE_THRESHOLD
from blinter.io.encoding import LineEndingInfo
from blinter.models import BlinterConfig, LintIssue
from blinter.parsing.visitors import ast_handled_rule_codes, check_ast_syntax_rules
from blinter.parsing.visitors.encoding_visitor import check_encoding_rules
from blinter.parsing.visitors.flow_visitor import check_flow_rules
from blinter.parsing.visitors.heuristic_visitors import (
    check_performance_rules,
    check_security_rules,
    check_style_rules,
    check_warning_rules,
)
from blinter.parsing.visitors.setlocal_visitor import check_setlocal_rules
from blinter.parsing.visitors.structure_visitor import check_structure_rules
from blinter.parsing.visitors.symbol_visitor import check_symbol_rules
from blinter.rules.helpers import _has_any_enabled_rules, _rule_codes_with_prefix

_ERROR_RULES = _rule_codes_with_prefix("E")
_WARNING_RULES = _rule_codes_with_prefix("W")
_STYLE_RULES = _rule_codes_with_prefix("S")
_SECURITY_RULES = _rule_codes_with_prefix("SEC")
_PERFORMANCE_RULES = _rule_codes_with_prefix("P")
_TEMP_PATH_RULE_PRIORITY: tuple[str, ...] = ("SEC012", "SEC017", "SEC007")


def _dedupe_temp_path_issues(issues: List[LintIssue]) -> List[LintIssue]:
    """Keep at most one temp-path SEC rule per line (most specific wins)."""
    winners_by_line: Dict[int, str] = {}
    for issue in issues:
        if issue.rule.code not in _TEMP_PATH_RULE_PRIORITY:
            continue
        current = winners_by_line.get(issue.line_number)
        if current is None:
            winners_by_line[issue.line_number] = issue.rule.code
            continue
        if _TEMP_PATH_RULE_PRIORITY.index(
            issue.rule.code
        ) < _TEMP_PATH_RULE_PRIORITY.index(current):
            winners_by_line[issue.line_number] = issue.rule.code

    if not winners_by_line:
        return issues

    seen_winners: Set[tuple[int, str]] = set()
    result: List[LintIssue] = []
    for issue in issues:
        if issue.rule.code not in _TEMP_PATH_RULE_PRIORITY:
            result.append(issue)
            continue
        winner = winners_by_line.get(issue.line_number)
        key = (issue.line_number, winner or "")
        if winner == issue.rule.code and key not in seen_winners:
            seen_winners.add(key)
            result.append(issue)
    return result


def _filter_ast_handled(issues: List[LintIssue]) -> List[LintIssue]:
    ast_codes = ast_handled_rule_codes()
    return [issue for issue in issues if issue.rule.code not in ast_codes]


def lint_via_ast(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    lines: List[str],
    labels: Dict[str, int],
    set_vars: Set[str],
    has_setlocal: bool,
    has_set_commands: bool,
    has_delayed_expansion: bool,
    uses_delayed_vars: bool,
    has_disable_delayed_expansion: bool,
    has_literal_exclamations: bool,
    has_disable_expansion_lines: bool,
    config: BlinterConfig,
    skip_lines: Optional[Set[int]] = None,
    called_scripts_vars: Optional[Dict[int, Set[str]]] = None,
    *,
    file_path: str = "",
    line_ending_info: Optional[LineEndingInfo] = None,
) -> List[LintIssue]:
    """Run all AST-first visitor passes for one batch file."""
    if skip_lines is None:
        skip_lines = set()

    issues: List[LintIssue] = []

    run_errors = _has_any_enabled_rules(config, _ERROR_RULES)
    run_warnings = _has_any_enabled_rules(config, _WARNING_RULES)
    run_style = _has_any_enabled_rules(config, _STYLE_RULES)
    run_security = _has_any_enabled_rules(config, _SECURITY_RULES)
    run_performance = _has_any_enabled_rules(config, _PERFORMANCE_RULES)

    issues.extend(
        check_encoding_rules(
            lines,
            file_path,
            ending_info=line_ending_info,
            run_style=run_style,
            run_warnings=run_warnings,
            run_errors=run_errors,
        )
    )

    for index, line in enumerate(lines, start=1):
        if index in skip_lines:
            continue

        line_issues: List[LintIssue] = []
        if run_errors:
            line_issues.extend(
                check_structure_rules(
                    line,
                    index,
                    labels,
                    lines=lines,
                )
            )
        line_issues = _filter_ast_handled(line_issues)
        issues.extend(line_issues)

        if run_warnings:
            issues.extend(
                check_warning_rules(
                    line,
                    index,
                    set_vars,
                    has_delayed_expansion,
                    lines=lines,
                )
            )

        if run_style:
            issues.extend(check_style_rules(line, index, lines, config.max_line_length))

        if run_security:
            issues.extend(check_security_rules(line, index, lines, labels))

        if run_performance:
            issues.extend(
                check_performance_rules(
                    lines,
                    index,
                    line,
                    has_setlocal,
                    has_set_commands,
                    has_delayed_expansion,
                    uses_delayed_vars,
                    has_disable_delayed_expansion,
                    has_literal_exclamations,
                    has_disable_expansion_lines,
                )
            )

    issues.extend(
        check_symbol_rules(
            lines,
            set_vars,
            called_scripts_vars,
            run_errors=run_errors,
        )
    )
    issues.extend(
        check_flow_rules(
            lines,
            run_errors=run_errors,
            run_warnings=run_warnings,
            run_style=run_style,
            run_security=run_security,
            run_performance=run_performance,
            config=config,
            file_path=file_path,
        )
    )
    issues.extend(
        check_setlocal_rules(
            lines,
            run_performance=run_performance,
            run_warnings=run_warnings,
        )
    )

    if run_security:
        issues[:] = _dedupe_temp_path_issues(issues)

    if run_errors:
        issues.extend(
            check_ast_syntax_rules(
                lines,
                has_delayed_expansion=has_delayed_expansion,
            )
        )

    return issues


def filter_issues_by_config(
    issues: List[LintIssue],
    config: BlinterConfig,
    suppressions: Dict[int, Set[str]],
) -> List[LintIssue]:
    """Filter issues based on configuration settings and inline suppressions."""
    filtered_issues = []
    for issue in issues:
        if not config.is_rule_enabled(issue.rule.code):
            continue
        if not config.should_include_severity(issue.rule.severity):
            continue
        if issue.line_number in suppressions:
            suppressed_codes = suppressions[issue.line_number]
            if not suppressed_codes or issue.rule.code in suppressed_codes:
                continue
        filtered_issues.append(issue)
    return filtered_issues
