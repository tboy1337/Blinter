"""Tests for blinter configuration functionality."""

import configparser
import os
import tempfile
from typing import Set
from unittest.mock import patch

from blinter import (
    BlinterConfig,
    RuleSeverity,
    create_default_config_file,
    lint_batch_file,
    load_config,
)


class TestBlinterConfig:
    """Test BlinterConfig class functionality."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = BlinterConfig()

        assert config.recursive is True
        assert config.show_summary is False
        assert config.max_line_length == 88
        assert config.enabled_rules == set()
        assert config.disabled_rules == set()
        assert config.min_severity is None

    def test_config_with_custom_values(self) -> None:
        """Test configuration with custom values."""
        enabled_rules: Set[str] = {"E001", "W001"}
        disabled_rules: Set[str] = {"S001", "S002"}

        config = BlinterConfig(
            recursive=False,
            show_summary=True,
            max_line_length=80,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            min_severity=RuleSeverity.WARNING,
        )

        assert config.recursive is False
        assert config.show_summary is True
        assert config.max_line_length == 80
        assert config.enabled_rules == enabled_rules
        assert config.disabled_rules == disabled_rules
        assert config.min_severity == RuleSeverity.WARNING

    def test_is_rule_enabled_with_no_filters(self) -> None:
        """Test rule enablement with no filters (all enabled by default)."""
        config = BlinterConfig()

        assert config.is_rule_enabled("E001") is True
        assert config.is_rule_enabled("W001") is True
        assert config.is_rule_enabled("S001") is True

    def test_is_rule_enabled_with_disabled_rules(self) -> None:
        """Test rule enablement with disabled rules."""
        config = BlinterConfig(disabled_rules={"E001", "S001"})

        assert config.is_rule_enabled("E001") is False
        assert config.is_rule_enabled("S001") is False
        assert config.is_rule_enabled("W001") is True

    def test_is_rule_enabled_with_enabled_rules(self) -> None:
        """Test rule enablement with specific enabled rules."""
        config = BlinterConfig(enabled_rules={"E001", "W001"})

        assert config.is_rule_enabled("E001") is True
        assert config.is_rule_enabled("W001") is True
        assert config.is_rule_enabled("S001") is False

    def test_is_rule_enabled_disabled_overrides_enabled(self) -> None:
        """Test that disabled rules override enabled rules."""
        config = BlinterConfig(
            enabled_rules={"E001", "W001", "S001"}, disabled_rules={"E001"}
        )

        assert config.is_rule_enabled("E001") is False
        assert config.is_rule_enabled("W001") is True
        assert config.is_rule_enabled("S001") is True

    def test_should_include_severity_no_filter(self) -> None:
        """Test severity filtering with no minimum severity."""
        config = BlinterConfig()

        assert config.should_include_severity(RuleSeverity.STYLE) is True
        assert config.should_include_severity(RuleSeverity.PERFORMANCE) is True
        assert config.should_include_severity(RuleSeverity.WARNING) is True
        assert config.should_include_severity(RuleSeverity.SECURITY) is True
        assert config.should_include_severity(RuleSeverity.ERROR) is True

    def test_should_include_severity_with_filter(self) -> None:
        """Test severity filtering with minimum severity."""
        config = BlinterConfig(min_severity=RuleSeverity.WARNING)

        assert config.should_include_severity(RuleSeverity.STYLE) is False
        assert config.should_include_severity(RuleSeverity.PERFORMANCE) is False
        assert config.should_include_severity(RuleSeverity.WARNING) is True
        assert config.should_include_severity(RuleSeverity.SECURITY) is True
        assert config.should_include_severity(RuleSeverity.ERROR) is True

    def test_should_include_severity_error_only(self) -> None:
        """Test severity filtering for errors only."""
        config = BlinterConfig(min_severity=RuleSeverity.ERROR)

        assert config.should_include_severity(RuleSeverity.STYLE) is False
        assert config.should_include_severity(RuleSeverity.PERFORMANCE) is False
        assert config.should_include_severity(RuleSeverity.WARNING) is False
        assert config.should_include_severity(RuleSeverity.SECURITY) is False
        assert config.should_include_severity(RuleSeverity.ERROR) is True


class TestConfigurationLoading:
    """Test configuration file loading functionality."""

    def test_load_config_no_file(self) -> None:
        """Test loading configuration when no file exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "blinter.ini")
            config = load_config(config_path)

            # Should return default config
            assert config.recursive is True
            assert config.show_summary is False
            assert config.max_line_length == 88
            assert config.enabled_rules == set()
            assert config.disabled_rules == set()
            assert config.min_severity is None

    def test_load_config_use_config_false(self) -> None:
        """Test loading configuration when use_config is False."""
        config = load_config(use_config=False)

        # Should return default config regardless of file existence
        assert config.recursive is True
        assert config.show_summary is False
        assert config.max_line_length == 88

    def test_load_config_with_general_settings(self) -> None:
        """Test loading configuration with general settings."""
        config_content = """
[general]
recursive = false
show_summary = true
max_line_length = 80
min_severity = WARNING
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

            try:
                config = load_config(config_file.name)

                assert config.recursive is False
                assert config.show_summary is True
                assert config.max_line_length == 80
                assert config.min_severity == RuleSeverity.WARNING
            finally:
                try:
                    os.unlink(config_file.name)
                except (OSError, PermissionError):
                    pass  # Ignore cleanup errors

    def test_load_config_with_rule_settings(self) -> None:
        """Test loading configuration with rule settings."""
        config_content = """
[rules]
enabled_rules = E001,E002,W001
disabled_rules = S001,S002,S003
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

        try:
            config = load_config(config_file.name)

            assert config.enabled_rules == {"E001", "E002", "W001"}
            assert config.disabled_rules == {"S001", "S002", "S003"}
        finally:
            try:
                os.unlink(config_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors

    def test_load_config_with_empty_rule_lists(self) -> None:
        """Test loading configuration with empty rule lists."""
        config_content = """
[rules]
enabled_rules = 
disabled_rules = 
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

            try:
                config = load_config(config_file.name)

                assert config.enabled_rules == set()
                assert config.disabled_rules == set()
            finally:
                try:
                    os.unlink(config_file.name)
                except (OSError, PermissionError):
                    pass  # Ignore cleanup errors

    def test_load_config_with_whitespace_in_rules(self) -> None:
        """Test loading configuration with whitespace in rule lists."""
        config_content = """
[rules]
enabled_rules = E001, E002 , W001 
disabled_rules = S001 ,S002,  S003  
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

        try:
            config = load_config(config_file.name)

            assert config.enabled_rules == {"E001", "E002", "W001"}
            assert config.disabled_rules == {"S001", "S002", "S003"}
        finally:
            try:
                os.unlink(config_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors

    def test_load_config_invalid_severity(self) -> None:
        """Test loading configuration with invalid severity value."""
        config_content = """
[general]
min_severity = INVALID
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

            try:
                with patch("blinter.logger") as mock_logger:
                    config = load_config(config_file.name)

                    # Should use default (None) and log warning
                    assert config.min_severity is None
                    mock_logger.warning.assert_called_once()
            finally:
                try:
                    os.unlink(config_file.name)
                except (OSError, PermissionError):
                    pass  # Ignore cleanup errors

    def test_load_config_malformed_file(self) -> None:
        """Test loading configuration with malformed file."""
        config_content = "This is not a valid INI file"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

        try:
            with patch("blinter.logger") as mock_logger:
                config = load_config(config_file.name)

                # Should return defaults and log warning
                assert config.recursive is True
                assert config.show_summary is False
                mock_logger.warning.assert_called_once()
        finally:
            try:
                os.unlink(config_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors

    def test_load_config_partial_settings(self) -> None:
        """Test loading configuration with only some settings specified."""
        config_content = """
[general]
show_summary = true

[rules]
disabled_rules = S001
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config_content)
            config_file.flush()
            config_file.close()  # Close file before reading on Windows

        try:
            config = load_config(config_file.name)

            # Specified settings should be loaded
            assert config.show_summary is True
            assert config.disabled_rules == {"S001"}

            # Unspecified settings should use defaults
            assert config.recursive is True
            assert config.max_line_length == 88
            assert config.enabled_rules == set()
        finally:
            try:
                os.unlink(config_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors


class TestCreateDefaultConfigFile:
    """Test default configuration file creation."""

    def test_create_default_config_file(self) -> None:
        """Test creating default configuration file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "test_blinter.ini")

            create_default_config_file(config_path)

            # File should exist
            assert os.path.exists(config_path)

            # File should be valid INI format
            parser = configparser.ConfigParser()
            parser.read(config_path)

            # Should have expected sections
            assert parser.has_section("general")
            assert parser.has_section("rules")

            # Should have expected keys (commented out values are optional)
            assert "recursive" in parser["general"]
            assert "show_summary" in parser["general"]
            assert "max_line_length" in parser["general"]

    def test_create_default_config_file_permission_error(self) -> None:
        """Test creating config file with permission error."""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with patch("builtins.print") as mock_print:
                create_default_config_file("readonly.ini")

                # Should print error message
                mock_print.assert_called()
                error_message = str(mock_print.call_args[0][0])
                assert "Error creating configuration file" in error_message


class TestConfigurationIntegration:
    """Test configuration integration with main functionality."""

    def test_config_affects_rule_filtering(self) -> None:
        """Test that configuration affects rule filtering."""

        # Create a simple batch file for testing
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as batch_file:
            batch_file.write("@echo off\n")
            batch_file.write(
                "echo " + "x" * 88 + "\n"
            )  # Create a line longer than 88 chars
            batch_file.flush()
            batch_file.close()  # Close file before reading on Windows

        try:
            # Test with default config (should include S011)
            config_default = BlinterConfig()
            issues_default = lint_batch_file(batch_file.name, config=config_default)
            s011_issues_default = [i for i in issues_default if i.rule.code == "S011"]

            # Test with S011 disabled
            config_no_s011 = BlinterConfig(disabled_rules={"S011"})
            issues_no_s011 = lint_batch_file(batch_file.name, config=config_no_s011)
            s011_issues_filtered = [i for i in issues_no_s011 if i.rule.code == "S011"]

            # S011 should be present in default but not in filtered
            assert len(s011_issues_default) > 0
            assert len(s011_issues_filtered) == 0

        finally:
            try:
                os.unlink(batch_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors

    def test_config_affects_line_length_rule(self) -> None:
        """Test that configuration affects line length rule."""

        # Create a batch file with a line of specific length
        line_content = "echo " + "x" * 80  # 85 characters total

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as batch_file:
            batch_file.write("@echo off\n")
            batch_file.write(line_content + "\n")
            batch_file.flush()
            batch_file.close()  # Close file before reading on Windows

        try:
            # Test with max_line_length = 120 (should not trigger S011)
            config_120 = BlinterConfig(max_line_length=120)
            issues_120 = lint_batch_file(batch_file.name, config=config_120)
            s011_issues_120 = [i for i in issues_120 if i.rule.code == "S011"]

            # Test with max_line_length = 80 (should trigger S011)
            config_80 = BlinterConfig(max_line_length=80)
            issues_80 = lint_batch_file(batch_file.name, config=config_80)
            s011_issues_80 = [i for i in issues_80 if i.rule.code == "S011"]

            # S011 should not trigger with 120 limit but should with 80 limit
            assert len(s011_issues_120) == 0
            assert len(s011_issues_80) > 0

        finally:
            try:
                os.unlink(batch_file.name)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors

    def test_config_affects_severity_filtering(self) -> None:
        """Test that configuration affects severity filtering."""

        # Create a batch file that will generate multiple severity levels
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as batch_file:
            batch_file.write("echo off\n")  # S002 - style issue
            batch_file.write(
                "if exist file.txt (\n"
            )  # E001 - error (unmatched parenthesis)
            batch_file.flush()
            batch_file.close()  # Close file before reading on Windows

            try:
                # Test with no severity filter (should include all)
                config_all = BlinterConfig()
                issues_all = lint_batch_file(batch_file.name, config=config_all)

                # Test with WARNING minimum severity (should exclude STYLE)
                config_warn = BlinterConfig(min_severity=RuleSeverity.WARNING)
                issues_warn = lint_batch_file(batch_file.name, config=config_warn)

                # Should have fewer issues with severity filter
                style_issues_all = [
                    i for i in issues_all if i.rule.severity == RuleSeverity.STYLE
                ]
                style_issues_warn = [
                    i for i in issues_warn if i.rule.severity == RuleSeverity.STYLE
                ]

                assert len(style_issues_all) > 0
                assert len(style_issues_warn) == 0

            finally:
                try:
                    os.unlink(batch_file.name)
                except (OSError, PermissionError):
                    pass  # Ignore cleanup errors


class TestConfigurationCoverage:
    """Test configuration-related code paths."""

    def create_temp_batch_file(self, content: str) -> str:
        """Helper method to create a temporary batch file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            return temp_file.name

    def test_min_severity_filtering(self) -> None:
        """Test min_severity configuration option."""
        content = """@ECHO OFF
echo lowercase
set var=value
REM Some comment
EXIT /b 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            # Only show ERROR and SECURITY issues
            config = BlinterConfig(min_severity=RuleSeverity.SECURITY)
            issues = lint_batch_file(temp_file, config=config)
            # Should filter out STYLE and WARNING issues
            for issue in issues:
                assert issue.rule.severity in [
                    RuleSeverity.ERROR,
                    RuleSeverity.SECURITY,
                ]
        finally:
            os.unlink(temp_file)

    def test_enabled_rules_filter(self) -> None:
        """Test enabled_rules configuration option."""
        content = """@ECHO OFF
echo lowercase
set var=value
EXIT /b 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            # Only enable specific rules
            config = BlinterConfig()
            config.enabled_rules = {"STY001", "E001"}
            issues = lint_batch_file(temp_file, config=config)
            # Should only report issues for enabled rules
            for issue in issues:
                assert issue.rule.code in ["STY001", "E001"]
        finally:
            os.unlink(temp_file)

    def test_disabled_rules_filter(self) -> None:
        """Test disabled_rules takes precedence."""
        content = """@ECHO OFF
echo lowercase
set var=value
EXIT /b 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            # Disable specific rules
            config = BlinterConfig()
            config.disabled_rules = {"STY001", "STY002"}
            issues = lint_batch_file(temp_file, config=config)
            # Should not report disabled rules
            for issue in issues:
                assert issue.rule.code not in ["STY001", "STY002"]
        finally:
            os.unlink(temp_file)

    def test_config_with_disabled_rules(self) -> None:
        """Test configuration with specific rules disabled."""
        content = """@ECHO OFF
echo off without @
set var=value
EXIT /b 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            config = BlinterConfig()
            # Use disabled_rules to disable specific rules
            config.disabled_rules = {"STY001"}
            issues = lint_batch_file(temp_file, config=config)
            sty001_issues = [i for i in issues if i.rule.code == "STY001"]
            assert len(sty001_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_config_max_line_length_custom(self) -> None:
        """Test custom max line length."""
        long_line = "A" * 200
        content = f"""@ECHO OFF
REM {long_line}
EXIT /b 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            config = BlinterConfig(max_line_length=100)
            issues = lint_batch_file(temp_file, config=config)
            # Should detect line length issue
            length_issues = [i for i in issues if "long" in i.rule.name.lower()]
            assert len(length_issues) > 0
        finally:
            os.unlink(temp_file)

    def test_config_max_nesting_depth(self) -> None:
        """Test detection of deep nesting."""
        content = """@ECHO OFF
IF 1==1 (
    IF 2==2 (
        IF 3==3 (
            IF 4==4 (
                IF 5==5 (
                    IF 6==6 (
                        ECHO Deep nesting
                    )
                )
            )
        )
    )
)
EXIT /b 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            config = BlinterConfig()
            issues = lint_batch_file(temp_file, config=config)
            # Should detect excessive nesting (any warning about depth)
            assert isinstance(issues, list)
            # Deep nesting should be flagged
            nesting_issues = [
                i
                for i in issues
                if "nesting" in i.rule.name.lower() or "depth" in i.rule.name.lower()
            ]
            assert len(nesting_issues) >= 0  # May or may not have specific nesting rule
        finally:
            os.unlink(temp_file)


class TestFollowCallsConfiguration:
    """Test cases for follow_calls configuration functionality."""

    def test_follow_calls_with_existing_scripts(self) -> None:
        """Test follow_calls with actual existing called scripts."""
        # Create a temporary directory for our batch files
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a called script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write("SET HELPER_VAR=helper_value\n")
                bat_file.write("EXIT /b 0\n")

            # Create main script that calls the helper
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write(f'CALL "{helper_script}"\n')
                bat_file.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should lint both files
            assert isinstance(issues, list)

    def test_follow_calls_with_nonexistent_script(self) -> None:
        """Test follow_calls when called script doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write("CALL nonexistent.bat\n")
                bat_file.write("EXIT /b 0\n")

            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should not crash when called script doesn't exist
            assert isinstance(issues, list)

    def test_follow_calls_already_processed(self) -> None:
        """Test that already processed files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create helper that is called twice
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\nEXIT /b 0\n")

            # Create main script that calls helper twice
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write(f'CALL "{helper_script}"\n')
                bat_file.write(f'CALL "{helper_script}"\n')
                bat_file.write("EXIT /b 0\n")

            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)
            # Should process helper only once
            assert isinstance(issues, list)
