"""JSON report serialization for CLI and tooling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from blinter.models import LintIssue, ProcessingResults
from blinter.output.formatters import compute_most_common_rule, compute_severity_counts
from blinter.rules.registry import RULES


def _serialize_issue(issue: LintIssue) -> dict[str, Any]:
    """Convert a LintIssue to a JSON-serializable dict."""
    return {
        "file": issue.file_path,
        "line": issue.line_number,
        "code": issue.rule.code,
        "name": issue.rule.name,
        "severity": issue.rule.severity.value,
        "explanation": issue.rule.explanation,
        "recommendation": issue.rule.recommendation,
        "context": issue.context,
    }


def _serialize_most_common_rule(
    issues: list[LintIssue],
) -> dict[str, Any] | None:
    """Return most common rule metadata, or None when there are no issues."""
    rule_code, count = compute_most_common_rule(issues)
    if not rule_code:
        return None
    rule_obj = RULES.get(rule_code)
    rule_name = rule_obj.name if rule_obj is not None else rule_code
    return {"code": rule_code, "name": rule_name, "count": count}


def build_report(
    results: ProcessingResults,
    target_path: str,
    version: str,
    fatal_issues: int,
) -> dict[str, Any]:
    """Build a JSON-serializable lint report from processing results."""
    issues = results.all_issues
    severity_counts = compute_severity_counts(issues)

    return {
        "blinter_version": version,
        "target": target_path,
        "is_directory": Path(target_path).is_dir(),
        "summary": {
            "total_issues": len(issues),
            "fatal_issues": fatal_issues,
            "files_processed": results.total_files_processed,
            "files_with_errors": results.files_with_errors,
            "severity_counts": {
                severity.value: count
                for severity, count in severity_counts.items()
            },
            "most_common_rule": _serialize_most_common_rule(issues),
        },
        "processed_files": [
            {"path": file_path, "called_by": called_by}
            for file_path, called_by in results.processed_file_paths
        ],
        "skipped_files": [
            {"path": file_path, "reason": reason}
            for file_path, reason in results.skipped_files
        ],
        "issues": [_serialize_issue(issue) for issue in issues],
    }


def _dumps_report(report: dict[str, Any]) -> str:
    """Serialize a report dict to a JSON string."""
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def write_report(path: str, report: dict[str, Any]) -> None:
    """Write a JSON report to the given file path."""
    Path(path).write_text(_dumps_report(report), encoding="utf-8")


def print_report(report: dict[str, Any]) -> None:
    """Print a JSON report to stdout."""
    print(_dumps_report(report), end="")
