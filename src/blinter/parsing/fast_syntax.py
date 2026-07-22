"""Fast line-scanner for grammar-backed syntax rules (E009, E011, E017, E019, E030-E033)."""

from __future__ import annotations

import re
from typing import List, Set

from blinter.models import LintIssue
from blinter.parsing.grammar_rules import GRAMMAR_BACKED_RULE_CODES
from blinter.parsing.preprocessor import map_line_number, preprocess_lines
from blinter.parsing.structure import _build_delayed_expansion_state
from blinter.parsing.visitors.rule_impl.advanced.escaping import (
    _check_continuation_spaces,
    _check_double_percent_escaping,
    _check_improper_caret_escape,
    _check_multilevel_escaping,
)
from blinter.parsing.visitors.rule_impl.advanced.vars_syntax import (
    _check_percent_tilde_syntax,
)
from blinter.parsing.visitors.rule_impl.syntax import (
    _check_quotes,
    _check_variable_expansion,
)
from blinter.rules.registry import RULES

_GRAMMAR_RULE_CODES: Set[str] = set(GRAMMAR_BACKED_RULE_CODES)


def _is_label_line(stripped: str) -> bool:
    """Return True when ``stripped`` is a batch label (``:name``, not ``::`` comment)."""
    return stripped.startswith(":") and not stripped.startswith("::")


def _collect_grammar_issues_for_line(
    *,
    physical_line: str,
    logical_line: str,
    line_number: int,
    lines: List[str],
    delayed_expansion_state: List[bool],
    seen: Set[tuple[int, str]],
) -> List[LintIssue]:
    """Run grammar-backed checks for one command line."""
    issues: List[LintIssue] = []
    stripped = physical_line.strip()
    logical_stripped = logical_line.strip()

    def add(code: str, context: str = "") -> None:
        key = (line_number, code)
        if key in seen or code not in _GRAMMAR_RULE_CODES:
            return
        rule = RULES.get(code)
        if rule is None:
            return
        seen.add(key)
        issues.append(LintIssue(line_number, rule, context=context))

    for issue in _check_variable_expansion(
        stripped,
        line_number,
        delayed_expansion_state=delayed_expansion_state,
    ):
        if issue.rule.code in _GRAMMAR_RULE_CODES:
            add(issue.rule.code, issue.context or "")
    for issue in _check_improper_caret_escape(stripped, line_number, physical_line):
        add(issue.rule.code, issue.context or "")
    for issue in _check_multilevel_escaping(stripped, line_number):
        add(issue.rule.code, issue.context or "")
    for issue in _check_continuation_spaces(physical_line, stripped, line_number):
        add(issue.rule.code, issue.context or "")
    for issue in _check_double_percent_escaping(stripped, line_number):
        add(issue.rule.code, issue.context or "")
    for issue in _check_percent_tilde_syntax(logical_stripped, line_number):
        add(issue.rule.code, issue.context or "")

    return issues


def check_grammar_backed_syntax_fast(
    lines: List[str],
    *,
    has_delayed_expansion: bool = False,
) -> List[LintIssue]:
    """
    Check grammar-backed syntax rules without invoking ANTLR.

    Mirrors ``SyntaxLintVisitor`` behaviour: E009 is evaluated per physical line;
    other rules run per preprocessed command line (first physical line for text
    checks, merged logical line for percent-tilde token scans).

    ``has_delayed_expansion`` is retained for API compatibility; bang-delimited
    E011 uses the per-line delayed-expansion stack from ``lines``.
    """
    del has_delayed_expansion
    delayed_expansion_state = _build_delayed_expansion_state(lines)
    preprocessed = preprocess_lines(lines)
    issues: List[LintIssue] = []
    seen: Set[tuple[int, str]] = set()

    for line_number, line in enumerate(lines, start=1):
        for issue in _check_quotes(line, line_number):
            key = (issue.line_number, issue.rule.code)
            if key in seen or issue.rule.code not in _GRAMMAR_RULE_CODES:
                continue
            seen.add(key)
            issues.append(issue)

    for preprocessed_line, logical_line in enumerate(preprocessed.lines, start=1):
        logical_stripped = logical_line.strip()
        if not logical_stripped or _is_label_line(logical_stripped):
            continue
        if re.match(r"rem\b", logical_stripped, re.IGNORECASE):
            continue

        original_line_number = map_line_number(preprocessed, preprocessed_line)
        if original_line_number < 1 or original_line_number > len(lines):
            continue
        physical_line = lines[original_line_number - 1]

        issues.extend(
            _collect_grammar_issues_for_line(
                physical_line=physical_line,
                logical_line=logical_line,
                line_number=original_line_number,
                lines=lines,
                delayed_expansion_state=delayed_expansion_state,
                seen=seen,
            )
        )

    for line_number, rule_code in preprocessed.continuation_issues:
        key = (line_number, rule_code)
        if key in seen or rule_code not in _GRAMMAR_RULE_CODES:
            continue
        rule = RULES.get(rule_code)
        if rule is None:
            continue
        seen.add(key)
        issues.append(LintIssue(line_number, rule, context=""))

    return issues
