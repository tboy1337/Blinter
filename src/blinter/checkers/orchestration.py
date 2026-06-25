"""Coordinates all checker categories for a parsed script."""

from typing import (
    Dict,
    List,
    Optional,
    Set,
)

from blinter.checkers.advanced import (
    _check_advanced_escaping_rules,
    _check_advanced_for_rules,
    _check_advanced_performance,
    _check_advanced_process_mgmt,
    _check_advanced_security,
    _check_advanced_style_patterns,
    _check_advanced_style_rules,
    _check_advanced_vars,
    _check_enhanced_commands,
    _check_enhanced_performance,
    _check_enhanced_security_rules,
)
from blinter.checkers.globals import (
    _check_cmd_case_consistency,
    _check_code_duplication,
    _check_inconsistent_indentation,
    _check_missing_exit_statement,
    _check_missing_header_doc,
    _check_missing_pause,
    _check_nested_paren_mismatch,
    _check_redundant_operations,
    _check_unreachable_code,
)
from blinter.checkers.performance import _check_performance_issues
from blinter.checkers.security import _check_security_issues
from blinter.checkers.style import _check_style_issues
from blinter.checkers.syntax import _check_syntax_errors
from blinter.checkers.vars import _check_undefined_variables
from blinter.checkers.warnings import _check_warning_issues
from blinter.models import BlinterConfig, LintIssue
from blinter.rules.helpers import _has_any_enabled_rules, _rule_codes_with_prefix

_ERROR_RULES = _rule_codes_with_prefix("E")
_WARNING_RULES = _rule_codes_with_prefix("W")
_STYLE_RULES = _rule_codes_with_prefix("S")
_SECURITY_RULES = _rule_codes_with_prefix("SEC")
_PERFORMANCE_RULES = _rule_codes_with_prefix("P")


def _append_line_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    issues: List[LintIssue],
    *,
    lines: List[str],
    line: str,
    line_number: int,
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
    run_errors: bool,
    run_warnings: bool,
    run_style: bool,
    run_security: bool,
    run_performance: bool,
) -> None:
    """Run enabled per-line checker groups for a single script line."""
    if run_errors:
        issues.extend(_check_syntax_errors(line, line_number, labels))
        issues.extend(_check_advanced_escaping_rules(line, line_number))

    if run_warnings:
        issues.extend(
            _check_warning_issues(line, line_number, set_vars, has_delayed_expansion)
        )
        issues.extend(_check_advanced_for_rules(line, line_number))
        issues.extend(_check_advanced_process_mgmt(line, line_number))

    if run_style:
        issues.extend(_check_style_issues(line, line_number, config.max_line_length))
        issues.extend(_check_advanced_style_patterns(line, line_number, lines))

    if run_security:
        issues.extend(_check_security_issues(line, line_number, lines))
        issues.extend(_check_advanced_security(line, line_number, lines, labels))

    if run_performance:
        issues.extend(
            _check_performance_issues(
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
        )
        issues.extend(_check_advanced_performance(lines, line_number, line))


def _append_global_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    issues: List[LintIssue],
    *,
    lines: List[str],
    set_vars: Set[str],
    called_scripts_vars: Optional[Dict[int, Set[str]]],
    config: BlinterConfig,
    run_errors: bool,
    run_warnings: bool,
    run_style: bool,
    run_security: bool,
    run_performance: bool,
) -> None:
    """Run enabled global checker groups across the full script."""
    if run_errors:
        issues.extend(_check_undefined_variables(lines, set_vars, called_scripts_vars))
        issues.extend(_check_nested_paren_mismatch(lines))
        issues.extend(_check_advanced_vars(lines))

    if run_warnings:
        issues.extend(_check_missing_exit_statement(lines))
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
        issues.extend(_check_cmd_case_consistency(lines))
        issues.extend(_check_advanced_style_rules(lines, config.max_line_length))


def _process_file_checks(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
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
) -> List[LintIssue]:
    """Process all line-by-line and global checks.

    Args:
        skip_lines: Optional set of line numbers to skip (e.g., embedded script blocks)
        called_scripts_vars: Optional dict mapping line numbers to variables from called scripts
    """
    issues: List[LintIssue] = []

    if skip_lines is None:
        skip_lines = set()

    run_errors = _has_any_enabled_rules(config, _ERROR_RULES)
    run_warnings = _has_any_enabled_rules(config, _WARNING_RULES)
    run_style = _has_any_enabled_rules(config, _STYLE_RULES)
    run_security = _has_any_enabled_rules(config, _SECURITY_RULES)
    run_performance = _has_any_enabled_rules(config, _PERFORMANCE_RULES)

    # Check each line with all rule categories
    for i, line in enumerate(lines, start=1):
        if i in skip_lines:
            continue

        _append_line_checks(
            issues,
            lines=lines,
            line=line,
            line_number=i,
            labels=labels,
            set_vars=set_vars,
            has_setlocal=has_setlocal,
            has_set_commands=has_set_commands,
            has_delayed_expansion=has_delayed_expansion,
            uses_delayed_vars=uses_delayed_vars,
            has_disable_delayed_expansion=has_disable_delayed_expansion,
            has_literal_exclamations=has_literal_exclamations,
            has_disable_expansion_lines=has_disable_expansion_lines,
            config=config,
            run_errors=run_errors,
            run_warnings=run_warnings,
            run_style=run_style,
            run_security=run_security,
            run_performance=run_performance,
        )

    _append_global_checks(
        issues,
        lines=lines,
        set_vars=set_vars,
        called_scripts_vars=called_scripts_vars,
        config=config,
        run_errors=run_errors,
        run_warnings=run_warnings,
        run_style=run_style,
        run_security=run_security,
        run_performance=run_performance,
    )

    return issues


def _filter_issues_by_config(
    issues: List[LintIssue],
    config: BlinterConfig,
    suppressions: Dict[int, Set[str]],
) -> List[LintIssue]:
    """
    Filter issues based on configuration settings and inline suppressions.

    Args:
        issues: List of all issues found during linting
        config: Configuration object with rule and severity settings
        suppressions: Dictionary mapping line numbers to sets of suppressed rule codes

    Returns:
        Filtered list of issues that should be reported
    """
    filtered_issues = []
    for issue in issues:
        # Check if rule is enabled
        if not config.is_rule_enabled(issue.rule.code):
            continue

        # Check if severity should be included
        if not config.should_include_severity(issue.rule.severity):
            continue

        # Check if issue is suppressed by inline comment
        if issue.line_number in suppressions:
            suppressed_codes = suppressions[issue.line_number]
            # Empty set means suppress all rules on this line
            if not suppressed_codes or issue.rule.code in suppressed_codes:
                continue

        filtered_issues.append(issue)

    return filtered_issues
