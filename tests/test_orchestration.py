"""Tests for checker orchestration helpers."""

from blinter.checkers.orchestration import _filter_issues_by_config
from blinter.models import BlinterConfig, LintIssue, Rule, RuleSeverity


def _issue(code: str, line: int = 1) -> LintIssue:
    return LintIssue(
        line_number=line,
        rule=Rule(
            code=code,
            name=f"Rule {code}",
            severity=RuleSeverity.ERROR,
            explanation="test",
            recommendation="test",
        ),
    )


class TestFilterIssuesByConfig:
    """Direct tests for issue filtering and inline suppressions."""

    def test_disabled_rules_filter(self) -> None:
        config = BlinterConfig(disabled_rules={"E001"})
        issues = [_issue("E001"), _issue("E002")]
        filtered = _filter_issues_by_config(issues, config, {})
        assert [issue.rule.code for issue in filtered] == ["E002"]

    def test_min_severity_filter(self) -> None:
        config = BlinterConfig(min_severity=RuleSeverity.SECURITY)
        issues = [
            LintIssue(
                line_number=1,
                rule=Rule(
                    code="W001",
                    name="Warning",
                    severity=RuleSeverity.WARNING,
                    explanation="test",
                    recommendation="test",
                ),
            ),
            LintIssue(
                line_number=2,
                rule=Rule(
                    code="SEC001",
                    name="Security",
                    severity=RuleSeverity.SECURITY,
                    explanation="test",
                    recommendation="test",
                ),
            ),
        ]
        filtered = _filter_issues_by_config(issues, config, {})
        assert [issue.rule.code for issue in filtered] == ["SEC001"]

    def test_inline_suppression_all_rules(self) -> None:
        config = BlinterConfig()
        issues = [_issue("E001", line=5), _issue("E002", line=6)]
        suppressions = {5: set()}
        filtered = _filter_issues_by_config(issues, config, suppressions)
        assert [issue.rule.code for issue in filtered] == ["E002"]

    def test_inline_suppression_specific_rule(self) -> None:
        config = BlinterConfig()
        issues = [_issue("E001", line=3), _issue("E002", line=3)]
        suppressions = {3: {"E001"}}
        filtered = _filter_issues_by_config(issues, config, suppressions)
        assert [issue.rule.code for issue in filtered] == ["E002"]

    def test_combined_filters(self) -> None:
        config = BlinterConfig(
            disabled_rules={"E002"},
            min_severity=RuleSeverity.ERROR,
        )
        issues = [
            _issue("E001", line=1),
            _issue("E002", line=2),
            LintIssue(
                line_number=3,
                rule=Rule(
                    code="W001",
                    name="Warning",
                    severity=RuleSeverity.WARNING,
                    explanation="test",
                    recommendation="test",
                ),
            ),
        ]
        suppressions = {1: set()}
        filtered = _filter_issues_by_config(issues, config, suppressions)
        assert [issue.rule.code for issue in filtered] == []
