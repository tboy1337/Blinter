"""Main lint orchestration entry point for single batch files."""

from collections import Counter
from pathlib import Path
from typing import (
    Dict,
    List,
    Optional,
    Set,
)

from blinter.engine.dependencies import _collect_called_vars
from blinter.engine.lines_cache import store_cached_lines
from blinter.io.encoding import _validate_and_read_file
from blinter.logging_config import logger
from blinter.models import BlinterConfig, LintIssue, RuleSeverity
from blinter.parsing.ast_pipeline import filter_issues_by_config, lint_via_ast
from blinter.parsing.embedded import _detect_embedded_script_blocks
from blinter.parsing.structure import (
    _analyze_script_structure,
    _begin_structure_cache_pass,
    _collect_labels,
    _collect_set_variables,
    _parse_suppression_comments,
)
from blinter.parsing.visitors.rule_impl.warnings import _begin_empty_assigned_vars_pass


def lint_batch_file(  # pylint: disable=too-many-locals
    file_path: str,
    config: Optional[BlinterConfig] = None,
    lines_cache: Optional[Dict[Path, List[str]]] = None,
) -> List[LintIssue]:
    """
    Lint a batch file and return list of issues found.

    Uses the unified AST-first pipeline (ANTLR parse tree + visitor passes).
    """
    logger.info("Starting lint analysis of file: %s", file_path)

    if Path(file_path).suffix.lower() not in {".bat", ".cmd"}:
        raise ValueError(f"File '{file_path}' is not a batch file (.bat or .cmd)")

    if config is None:
        config = BlinterConfig()

    scan_root = config.scan_root
    if scan_root is None:
        scan_root = str(Path(file_path).parent.resolve())

    lines, _encoding_used, line_ending_info = _validate_and_read_file(file_path)
    if lines_cache is not None:
        store_cached_lines(lines_cache, Path(file_path), lines)

    if not lines:
        return []

    _begin_structure_cache_pass()
    _begin_empty_assigned_vars_pass()

    skip_lines = _detect_embedded_script_blocks(lines)

    issues: List[LintIssue] = []

    structure_data = _analyze_script_structure(lines)
    (
        has_setlocal,
        has_set_commands,
        has_delayed_expansion,
        uses_delayed_vars,
        has_disable_delayed_expansion,
        has_literal_exclamations,
        has_disable_expansion_lines,
    ) = structure_data

    labels, label_issues = _collect_labels(lines)
    issues.extend(label_issues)

    set_vars = _collect_set_variables(lines)

    called_scripts_vars: Optional[Dict[int, Set[str]]] = None
    if config.follow_calls:
        try:
            batch_path = Path(file_path)
            called_scripts_vars = _collect_called_vars(
                batch_path,
                scan_root=scan_root,
                lines=lines,
                lines_cache=lines_cache,
            )
        except (OSError, ValueError) as collect_error:
            logger.warning(
                "Could not collect variables from called scripts for %s: %s",
                file_path,
                collect_error,
            )
            called_scripts_vars = None

    issues.extend(
        lint_via_ast(
            lines,
            labels,
            set_vars,
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
            has_disable_delayed_expansion,
            has_literal_exclamations,
            has_disable_expansion_lines,
            config,
            skip_lines,
            called_scripts_vars,
            file_path=file_path,
            line_ending_info=line_ending_info,
        )
    )

    for issue in issues:
        if issue.file_path is None:
            issue.file_path = file_path

    suppressions = _parse_suppression_comments(lines)
    filtered_issues = filter_issues_by_config(issues, config, suppressions)

    severity_counts = Counter(issue.rule.severity for issue in filtered_issues)
    logger.info(
        "Lint analysis completed. Found %d issues (filtered to %d) across %d error(s), "
        "%d warning(s), %d style issue(s), %d security issue(s), "
        "%d performance issue(s)",
        len(issues),
        len(filtered_issues),
        severity_counts[RuleSeverity.ERROR],
        severity_counts[RuleSeverity.WARNING],
        severity_counts[RuleSeverity.STYLE],
        severity_counts[RuleSeverity.SECURITY],
        severity_counts[RuleSeverity.PERFORMANCE],
    )

    return filtered_issues
