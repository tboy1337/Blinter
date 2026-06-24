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

    # Check each line with all rule categories
    for i, line in enumerate(lines, start=1):
        # Skip lines that are part of embedded scripts
        if i in skip_lines:
            continue

        # Error level checks
        issues.extend(_check_syntax_errors(line, i, labels))

        # Advanced escaping rules (E030-E033)
        issues.extend(_check_advanced_escaping_rules(line, i))

        # Warning level checks
        issues.extend(_check_warning_issues(line, i, set_vars, has_delayed_expansion))

        # Advanced FOR command rules (W034-W043)
        issues.extend(_check_advanced_for_rules(line, i))
        issues.extend(_check_advanced_process_mgmt(line, i))

        # Style level checks
        style_issues = _check_style_issues(line, i, config.max_line_length)
        issues.extend(style_issues)

        # Advanced style patterns (S022-S028)
        issues.extend(_check_advanced_style_patterns(line, i, lines))

        # Security level checks (always enabled for safety)
        issues.extend(_check_security_issues(line, i, lines))

        # Advanced security patterns (SEC014-SEC019)
        issues.extend(_check_advanced_security(line, i, lines, labels))

        # Performance level checks
        perf_issues = _check_performance_issues(
            lines,
            i,
            line,
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
            has_disable_delayed_expansion,
            has_literal_exclamations,
            has_disable_expansion_lines,
        )
        issues.extend(perf_issues)

        # Advanced performance patterns (P016-P025)
        issues.extend(_check_advanced_performance(lines, i, line))

    # Global checks (across all lines)
    issues.extend(_check_undefined_variables(lines, set_vars, called_scripts_vars))
    issues.extend(_check_missing_exit_statement(lines))
    issues.extend(_check_nested_paren_mismatch(lines))
    issues.extend(_check_unreachable_code(lines))
    issues.extend(_check_redundant_operations(lines))
    issues.extend(_check_code_duplication(lines))

    # Enhanced validation checks based on comprehensive batch scripting guide
    issues.extend(_check_advanced_vars(lines))  # Error level E017-E022
    issues.extend(_check_enhanced_commands(lines))  # Warning level W020-W025
    issues.extend(_check_enhanced_security_rules(lines))  # Security level SEC011-SEC013

    # Global checks that depend on configuration flags
    issues.extend(_check_missing_pause(lines))  # Warning level

    # Style-level global checks
    issues.extend(_check_inconsistent_indentation(lines))
    issues.extend(_check_missing_header_doc(lines))
    issues.extend(_check_cmd_case_consistency(lines))  # S003
    issues.extend(
        _check_advanced_style_rules(lines, config.max_line_length)
    )  # Style level S017-S020

    # Performance-level global checks
    issues.extend(_check_enhanced_performance(lines))  # Performance level P012-P014

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
