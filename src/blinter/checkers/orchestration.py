"""Re-export AST pipeline orchestration (legacy module path)."""

from blinter.parsing.ast_pipeline import (
    _dedupe_temp_path_issues,
    filter_issues_by_config as _filter_issues_by_config,
    lint_via_ast as _process_file_checks,
)

__all__ = [
    "_process_file_checks",
    "_filter_issues_by_config",
    "_dedupe_temp_path_issues",
]
