"""Shared helpers for constructing LintIssue instances."""
from typing import List, Optional
from blinter.models import LintIssue, Rule, RuleSeverity
from blinter.rules.registry import RULES

def _s011_rule(max_line_length: int) -> Rule:
    """Return the S011 rule, with explanation adjusted for custom line length."""
    base_rule = RULES["S011"]
    if max_line_length == 100:
        return base_rule
    return Rule(
        code=base_rule.code,
        name=base_rule.name,
        severity=base_rule.severity,
        explanation=base_rule.explanation.replace("100", str(max_line_length)),
        recommendation=base_rule.recommendation,
    )

def _add_issue(
    issues: List[LintIssue],
    line_number: int,
    rule_code: str,
    context: str = "",
    file_path: Optional[str] = None,
) -> None:
    """
    Add a linting issue to the issues list.

    This helper function reduces code duplication by centralizing the pattern of
    creating and appending LintIssue objects.

    Args:
        issues: List to append the issue to
        line_number: Line number where the issue occurs
        rule_code: Code of the rule being violated (e.g., "E001")
        context: Additional context about the issue
        file_path: Optional path to the file containing the issue

    Thread-safe: Yes - only appends to provided list (caller manages thread safety)
    """
    issues.append(
        LintIssue(
            line_number=line_number,
            rule=RULES[rule_code],
            context=context,
            file_path=file_path,
        )
    )

def _create_rule(
    code: str,
    name: str,
    severity: RuleSeverity,
    explanation: str,
    recommendation: str,
) -> Rule:
    """
    Create a Rule object with validation.

    This helper centralizes rule creation and provides a consistent interface.

    Args:
        code: Rule code (e.g., "E001")
        name: Short name of the rule
        severity: Rule severity level
        explanation: Detailed explanation of what the rule checks
        recommendation: How to fix violations of this rule

    Returns:
        Rule: Validated Rule object
    """
    return Rule(
        code=code,
        name=name,
        severity=severity,
        explanation=explanation,
        recommendation=recommendation,
    )
