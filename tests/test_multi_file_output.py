"""
Tests for multi-file output formatting with --follow-calls.

This module tests that when --follow-calls is enabled and multiple files are
processed, issues are properly displayed with file annotations to distinguish
which file each line number belongs to.
"""

import os
import tempfile

from blinter import (
    BlinterConfig,
    LintIssue,
    Rule,
    RuleSeverity,
    _format_line_numbers_with_files,
    lint_batch_file,
)


class TestFormatLineNumbersWithFiles:
    """Test the _format_line_numbers_with_files helper function."""

    def test_single_file_no_annotation(self) -> None:
        """Single file should not show filename annotations."""
        rule = Rule(
            code="E001",
            name="Test Rule",
            severity=RuleSeverity.ERROR,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        issues = [
            LintIssue(line_number=10, rule=rule, file_path="test.bat"),
            LintIssue(line_number=20, rule=rule, file_path="test.bat"),
            LintIssue(line_number=30, rule=rule, file_path="test.bat"),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        assert is_multi_file is False
        assert result == "Line 10, 20, 30"
        assert "[" not in result  # No file annotations

    def test_no_file_path_no_annotation(self) -> None:
        """Issues without file_path should use simple format."""
        rule = Rule(
            code="E001",
            name="Test Rule",
            severity=RuleSeverity.ERROR,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        issues = [
            LintIssue(line_number=10, rule=rule),
            LintIssue(line_number=20, rule=rule),
            LintIssue(line_number=30, rule=rule),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        assert is_multi_file is False
        assert result == "Line 10, 20, 30"
        assert "[" not in result  # No file annotations

    def test_multiple_files_with_annotations(self) -> None:
        """Multiple files should show filename annotations."""
        rule = Rule(
            code="E006",
            name="Undefined variable",
            severity=RuleSeverity.ERROR,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        issues = [
            LintIssue(line_number=296, rule=rule, file_path="helper.bat"),
            LintIssue(line_number=303, rule=rule, file_path="helper.bat"),
            LintIssue(line_number=4709, rule=rule, file_path="main.bat"),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        assert is_multi_file is True
        assert isinstance(result, dict)
        assert "helper.bat" in result
        assert "main.bat" in result
        assert result["helper.bat"] == [296, 303]
        assert result["main.bat"] == [4709]

    def test_full_path_shows_basename_only(self) -> None:
        """Full paths should be reduced to just the filename."""
        rule = Rule(
            code="E006",
            name="Undefined variable",
            severity=RuleSeverity.ERROR,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        issues = [
            LintIssue(
                line_number=10, rule=rule, file_path="C:\\Users\\test\\helper.bat"
            ),
            LintIssue(
                line_number=20, rule=rule, file_path="D:\\projects\\scripts\\main.bat"
            ),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        assert is_multi_file is True
        assert isinstance(result, dict)
        assert "helper.bat" in result
        assert "main.bat" in result
        assert result["helper.bat"] == [10]
        assert result["main.bat"] == [20]

    def test_mixed_file_path_and_none(self) -> None:
        """Issues with mixed file_path (some None) should handle gracefully."""
        rule = Rule(
            code="E001",
            name="Test Rule",
            severity=RuleSeverity.ERROR,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        issues = [
            LintIssue(line_number=10, rule=rule, file_path="test.bat"),
            LintIssue(line_number=20, rule=rule),  # No file_path
            LintIssue(line_number=30, rule=rule, file_path="other.bat"),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        # Should show multi-file format since we have multiple files
        assert is_multi_file is True
        assert isinstance(result, dict)
        assert "test.bat" in result
        assert "other.bat" in result
        assert result["test.bat"] == [10]
        assert result["other.bat"] == [30]
        # Note: Line 20 without file_path is not included in multi-file mode

    def test_sorting_by_file_and_line(self) -> None:
        """Issues should be sorted by file path then line number."""
        rule = Rule(
            code="E001",
            name="Test Rule",
            severity=RuleSeverity.ERROR,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        # Add issues in random order
        issues = [
            LintIssue(line_number=4709, rule=rule, file_path="main.bat"),
            LintIssue(line_number=303, rule=rule, file_path="helper.bat"),
            LintIssue(line_number=296, rule=rule, file_path="helper.bat"),
            LintIssue(line_number=305, rule=rule, file_path="helper.bat"),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        # Should be sorted by file then line
        assert is_multi_file is True
        assert isinstance(result, dict)
        assert "helper.bat" in result
        assert "main.bat" in result
        # Lines should be sorted within each file
        assert result["helper.bat"] == [296, 303, 305]
        assert result["main.bat"] == [4709]

    def test_three_files_with_annotations(self) -> None:
        """Three or more files should all show annotations."""
        rule = Rule(
            code="W001",
            name="Test Warning",
            severity=RuleSeverity.WARNING,
            explanation="Test explanation",
            recommendation="Test recommendation",
        )

        issues = [
            LintIssue(line_number=10, rule=rule, file_path="script1.bat"),
            LintIssue(line_number=20, rule=rule, file_path="script2.bat"),
            LintIssue(line_number=30, rule=rule, file_path="script3.bat"),
        ]

        is_multi_file, result = _format_line_numbers_with_files(issues)
        assert is_multi_file is True
        assert isinstance(result, dict)
        assert "script1.bat" in result
        assert "script2.bat" in result
        assert "script3.bat" in result
        assert result["script1.bat"] == [10]
        assert result["script2.bat"] == [20]
        assert result["script3.bat"] == [30]


class TestFollowCallsOutputIntegration:
    """Integration tests for multi-file output with --follow-calls."""

    def test_follow_calls_single_main_file_no_annotations(self) -> None:
        """Single main file without calls should not show annotations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create single main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write("ECHO %UNDEFINED_VAR%\n")
                batch_file.write("EXIT /b 0\n")

            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # All issues should have file_path set to main_script
            for issue in issues:
                assert issue.file_path == main_script

    def test_follow_calls_with_helper_shows_annotations(self) -> None:
        """Main file calling helper should properly track file paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create helper script with undefined variable
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write("ECHO Using undefined: %HELPER_UNDEFINED%\n")
                batch_file.write("EXIT /b 0\n")

            # Create main script that calls helper and has its own issue
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write(f'CALL "{helper_script}"\n')
                batch_file.write("ECHO Using undefined: %MAIN_UNDEFINED%\n")
                batch_file.write("EXIT /b 0\n")

            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Check that issues have correct file_path
            main_issues = [i for i in issues if i.file_path == main_script]
            assert len(main_issues) > 0, "Should have issues from main script"

            # When follow_calls is enabled, issues from main should have main_script path
            undefined_issues = [i for i in issues if i.rule.code == "E006"]
            main_undefined = [
                i for i in undefined_issues if "MAIN_UNDEFINED" in i.context
            ]
            assert len(main_undefined) > 0, "Should have E006 for MAIN_UNDEFINED"
            assert all(i.file_path == main_script for i in main_undefined)

    def test_called_script_issues_have_correct_file_path(self) -> None:
        """Issues from called scripts should have their own file_path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create helper script with an issue
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write("REM Missing exit code\n")

            # Create main script that calls helper
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write(f'CALL "{helper_script}"\n')
                batch_file.write("EXIT /b 0\n")

            config = BlinterConfig(follow_calls=True)

            # Lint just the helper directly to see what issues it has
            helper_issues = lint_batch_file(helper_script, config=config)

            # All issues should have helper_script as file_path
            for issue in helper_issues:
                assert issue.file_path == helper_script

    def test_relative_path_call_preserves_file_tracking(self) -> None:
        """Relative path calls should preserve file tracking."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create helper script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write("ECHO test\n")
                batch_file.write("EXIT /b 0\n")

            # Create main script with relative path call
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as batch_file:
                batch_file.write("@ECHO OFF\n")
                batch_file.write("CALL helper.bat\n")
                batch_file.write("EXIT /b 0\n")

            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # All issues should have valid file paths
            for issue in issues:
                assert issue.file_path is not None
                assert os.path.exists(issue.file_path)
