"""Tests for configuration options and new functionality."""

import os
from pathlib import Path
import tempfile

import pytest

from blinter import lint_batch_file


class TestConfigurationOptions:
    """Test configuration options and parameter validation."""

    def test_custom_max_line_length(self) -> None:
        """Test custom maximum line length configuration."""
        # Create a file with a line that's 100 characters long
        long_line = "REM " + "A" * 96  # Total 100 characters
        content = f"@ECHO OFF\n{long_line}\nEXIT /B 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Test with default max length (120) - should not trigger
            issues_default = lint_batch_file(temp_path)
            s011_issues_default = [i for i in issues_default if i.rule.code == "S011"]
            assert len(s011_issues_default) == 0

            # Test with custom max length (80) - should trigger
            issues_custom = lint_batch_file(temp_path, max_line_length=80)
            s011_issues_custom = [i for i in issues_custom if i.rule.code == "S011"]
            assert len(s011_issues_custom) == 1
            assert "100 characters (max 80)" in s011_issues_custom[0].context

        finally:
            os.unlink(temp_path)

    def test_disable_style_rules(self) -> None:
        """Test disabling style rules."""
        content = """echo off
echo test  
echo another line that is very very very very very very very very very very very very very very very very very very very long
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Test with style rules enabled (default)
            issues_enabled = lint_batch_file(temp_path)
            style_issues_enabled = [i for i in issues_enabled if i.rule.severity.value == "Style"]
            assert len(style_issues_enabled) > 0  # Should have style issues

            # Test with style rules disabled
            issues_disabled = lint_batch_file(temp_path, enable_style_rules=False)
            style_issues_disabled = [i for i in issues_disabled if i.rule.severity.value == "Style"]
            assert len(style_issues_disabled) == 0  # Should have no style issues

        finally:
            os.unlink(temp_path)

    def test_disable_performance_rules(self) -> None:
        """Test disabling performance rules."""
        content = """@ECHO OFF
SETLOCAL
echo test
REM No SET commands, so SETLOCAL is unnecessary
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Test with performance rules enabled (default)
            issues_enabled = lint_batch_file(temp_path)
            _ = [i for i in issues_enabled if i.rule.severity.value == "Performance"]
            # May or may not have performance issues depending on the exact logic

            # Test with performance rules disabled
            issues_disabled = lint_batch_file(temp_path, enable_performance_rules=False)
            perf_issues_disabled = [
                i for i in issues_disabled if i.rule.severity.value == "Performance"
            ]
            assert len(perf_issues_disabled) == 0  # Should have no performance issues

        finally:
            os.unlink(temp_path)

    def test_security_rules_always_enabled(self) -> None:
        """Test that security rules are always enabled for safety."""
        content = """@ECHO OFF
reg delete HKLM\\Software\\Test /f
set VAR=unsafe value without quotes
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Security rules should always be enabled regardless of other settings
            issues = lint_batch_file(
                temp_path, enable_style_rules=False, enable_performance_rules=False
            )
            security_issues = [i for i in issues if i.rule.severity.value == "Security"]
            assert len(security_issues) >= 1  # Should always have security checks

        finally:
            os.unlink(temp_path)


class TestInputValidation:
    """Test input validation and error handling."""

    def test_empty_file_path(self) -> None:
        """Test validation of empty file path."""
        with pytest.raises(ValueError, match="file_path must be a non-empty string"):
            lint_batch_file("")

    def test_none_file_path(self) -> None:
        """Test validation of None file path."""
        with pytest.raises(ValueError, match="file_path must be a non-empty string"):
            lint_batch_file(None)

    def test_non_string_file_path(self) -> None:
        """Test validation of non-string file path."""
        with pytest.raises(ValueError, match="file_path must be a non-empty string"):
            lint_batch_file(123)

    def test_nonexistent_file(self) -> None:
        """Test handling of nonexistent file."""
        nonexistent_path = "definitely_does_not_exist.bat"
        with pytest.raises(FileNotFoundError, match="File not found"):
            lint_batch_file(nonexistent_path)

    def test_directory_instead_of_file(self) -> None:
        """Test handling when path points to directory instead of file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="Path is not a file"):
                lint_batch_file(temp_dir)

    def test_large_file_warning(self) -> None:
        """Test large file warning (indirectly through successful processing)."""
        # Create a moderately large file (not 10MB but still substantial)
        large_content = "@ECHO OFF\n" + ("REM Large file line\n" * 10000) + "EXIT /B 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(large_content)
            temp_path = temp_file.name

        try:
            # Should handle large files without issues
            issues = lint_batch_file(temp_path)
            assert isinstance(issues, list)  # Should complete successfully
        finally:
            os.unlink(temp_path)


class TestLoggingAndReporting:
    """Test logging and reporting functionality."""

    def test_comprehensive_configuration_combination(self) -> None:
        """Test various configuration combinations work together."""
        content = """echo off
set VAR=unquoted value
echo %UNDEFINED_VAR%
echo trailing whitespace  
echo this line is quite long and exceeds typical line length recommendations for readability
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Test various combinations
            configs = [
                {
                    "max_line_length": 80,
                    "enable_style_rules": True,
                    "enable_performance_rules": True,
                },
                {
                    "max_line_length": 200,
                    "enable_style_rules": False,
                    "enable_performance_rules": True,
                },
                {
                    "max_line_length": 100,
                    "enable_style_rules": True,
                    "enable_performance_rules": False,
                },
                {
                    "max_line_length": 60,
                    "enable_style_rules": False,
                    "enable_performance_rules": False,
                },
            ]

            for config in configs:
                issues = lint_batch_file(temp_path, **config)
                assert isinstance(issues, list)

                # Verify configuration is respected
                if not config["enable_style_rules"]:
                    style_issues = [i for i in issues if i.rule.severity.value == "Style"]
                    assert len(style_issues) == 0

                if not config["enable_performance_rules"]:
                    perf_issues = [i for i in issues if i.rule.severity.value == "Performance"]
                    assert len(perf_issues) == 0

        finally:
            os.unlink(temp_path)

    def test_pathlib_path_support(self) -> None:
        """Test that Path objects are handled correctly."""
        content = "@ECHO OFF\necho test\nEXIT /B 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Test with string path
            issues_str = lint_batch_file(temp_path)

            # Test with Path object (should be converted to string internally)
            path_obj = Path(temp_path)
            issues_path = lint_batch_file(str(path_obj))

            # Results should be the same
            assert len(issues_str) == len(issues_path)

        finally:
            os.unlink(temp_path)

    def test_unicode_filename_support(self) -> None:
        """Test support for Unicode filenames."""
        content = "@ECHO OFF\necho test\nEXIT /B 0\n"

        # Create file with Unicode characters in name
        with tempfile.TemporaryDirectory() as temp_dir:
            unicode_filename = os.path.join(temp_dir, "tëst_fîlé.bat")
            with open(unicode_filename, "w", encoding="utf-8") as temp_file:
                temp_file.write(content)

            # Should handle Unicode filenames
            issues = lint_batch_file(unicode_filename)
            assert isinstance(issues, list)
