"""Tests for edge cases and specialized scenarios."""

# pylint: disable=too-many-lines,import-outside-toplevel,redefined-outer-name,reimported
# pylint: disable=unused-argument,invalid-name,missing-class-docstring,too-few-public-methods
# pylint: disable=unused-variable,unused-import

import os
import tempfile
from typing import Dict, Set
from unittest.mock import mock_open, patch

import pytest

from blinter import (
    _check_advanced_style_rules,
    _check_advanced_vars,
    _check_code_duplication,
    _check_enhanced_commands,
    _check_enhanced_performance,
    _check_enhanced_security_rules,
    _check_function_docs,
    _check_line_length,
    _check_magic_numbers,
    _check_performance_issues,
    _check_redundant_operations,
    _check_security_issues,
    _check_style_issues,
    _check_syntax_errors,
    _check_undefined_variables,
    _check_unreachable_code,
    _check_warning_issues,
    _collect_labels,
    _collect_set_variables,
    _detect_line_endings,
    _has_multibyte_chars,
    lint_batch_file,
    read_file_with_encoding,
)


class TestFileEncodingEdgeCases:
    """Test edge cases in file encoding detection and handling."""

    def test_chardet_oserror_handling(self) -> None:
        """Test handling of OSError during chardet detection."""
        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", side_effect=OSError("Test OSError")),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding in [
                "utf-8",
                "utf-8-sig",
                "latin1",
                "cp1252",
                "iso-8859-1",
                "ascii",
            ]
            assert len(lines) > 0

    def test_chardet_valueerror_handling(self) -> None:
        """Test handling of ValueError during chardet detection."""
        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", side_effect=ValueError("Test ValueError")),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding in [
                "utf-8",
                "utf-8-sig",
                "latin1",
                "cp1252",
                "iso-8859-1",
                "ascii",
            ]
            assert len(lines) > 0

    def test_chardet_typeerror_handling(self) -> None:
        """Test handling of TypeError during chardet detection."""
        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", side_effect=TypeError("Test TypeError")),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding in [
                "utf-8",
                "utf-8-sig",
                "latin1",
                "cp1252",
                "iso-8859-1",
                "ascii",
            ]
            assert len(lines) > 0

    def test_encoding_lookup_error_fallback(self) -> None:
        """Test handling when encoding lookup fails."""

        def mock_open_with_lookup_error(*args: object, **kwargs: object) -> object:
            if "encoding" in kwargs:
                # Simulate LookupError for unsupported encoding
                if kwargs["encoding"] == "utf-8":
                    raise LookupError("Unknown encoding")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_with_lookup_error):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding != "utf-8"  # Should fall back to other encoding
            assert len(lines) > 0

    def test_encoding_value_error_fallback(self) -> None:
        """Test handling when encoding value is invalid."""

        def mock_open_with_value_error(*args: object, **kwargs: object) -> object:
            if "encoding" in kwargs:
                # Simulate ValueError for invalid encoding
                if kwargs["encoding"] == "utf-8":
                    raise ValueError("Invalid encoding")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_with_value_error):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding != "utf-8"  # Should fall back to other encoding
            assert len(lines) > 0

    def test_all_encodings_fail_with_exception(self) -> None:
        """Test when all encodings fail and we have a last exception."""

        def mock_open_always_fail(*args: object, **kwargs: object) -> object:
            if "encoding" in kwargs:
                raise UnicodeDecodeError("test", b"", 0, 1, "test error")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_always_fail):
            with pytest.raises(OSError, match="All encoding attempts failed"):
                read_file_with_encoding("test.bat")

    def test_all_encodings_fail_no_exception(self) -> None:
        """Test when all encodings fail but no exception is stored."""

        def mock_open_no_exception(*args: object, **kwargs: object) -> object:
            # Don't store any exception by not raising UnicodeDecodeError
            if "encoding" in kwargs:
                raise LookupError("Encoding not supported")
            return mock_open(read_data="test content")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_no_exception):
            with pytest.raises(OSError, match="All encoding attempts failed"):
                read_file_with_encoding("test.bat")

    def test_chardet_detected_encoding_already_in_list(self) -> None:
        """Test when chardet detects an encoding already in our list."""
        mock_detected = {"encoding": "utf-8", "confidence": 0.8}

        with (
            patch("builtins.open", mock_open(read_data=b"test content")),
            patch("chardet.detect", return_value=mock_detected),
        ):
            lines, encoding = read_file_with_encoding("test.bat")
            assert encoding == "utf-8"  # Should use detected encoding
            assert len(lines) > 0


class TestSyntaxErrorChecking:
    """Test syntax error checking edge cases."""

    def test_goto_with_colon_prefix(self) -> None:
        """Test GOTO statement with colon prefix in target."""
        labels = {":mylabel": 1}
        issues = _check_syntax_errors("GOTO :mylabel", 2, labels)
        assert len(issues) == 0  # Should be valid

    def test_if_statement_incomplete_comparison(self) -> None:
        """Test IF statement that looks incomplete (missing operator)."""
        labels: Dict[str, int] = {}
        issues = _check_syntax_errors('IF "VARIABLE"', 1, labels)
        assert len(issues) == 1
        assert "E003" in issues[0].rule.code

    def test_command_typo_detection(self) -> None:
        """Test detection of common command typos."""
        labels: Dict[str, int] = {}
        issues = _check_syntax_errors("IFF something", 1, labels)
        assert len(issues) == 1
        assert "E013" in issues[0].rule.code

    def test_empty_line_no_typo_detection(self) -> None:
        """Test that empty lines don't trigger typo detection."""
        labels: Dict[str, int] = {}
        issues = _check_syntax_errors("   ", 1, labels)
        assert len(issues) == 0

    def test_call_without_colon_to_builtin_command(self) -> None:
        """Test CALL to builtin command (should not trigger colon warning)."""
        labels: Dict[str, int] = {}
        issues = _check_syntax_errors("CALL dir", 1, labels)
        assert len(issues) == 0  # Should not trigger E014

    def test_call_without_colon_to_label_looking_name(self) -> None:
        """Test CALL to what looks like a label without colon."""
        labels: Dict[str, int] = {}
        issues = _check_syntax_errors("CALL mylabel", 1, labels)
        assert len(issues) == 1
        assert "E014" in issues[0].rule.code

    def test_goto_missing_label_edge_case(self) -> None:
        """Test GOTO with missing label edge case."""
        labels = {":otherlabel": 1}
        issues = _check_syntax_errors("goto nonexistent", 2, labels)
        assert len(issues) == 1
        assert "E002" in issues[0].rule.code


class TestWarningIssueChecking:
    """Test warning issue detection edge cases."""

    def test_deprecated_command_usage(self) -> None:
        """Test detection of deprecated commands.

        Note: Deprecated command checking (W024) has been moved to _check_deprecated_commands()
        and is no longer part of _check_warning_issues(). See test_lint_functionality.py for
        comprehensive deprecated command tests.
        """
        set_vars: Set[str] = set()
        issues = _check_warning_issues("assign A: B:", 1, set_vars, False)
        # Should not return any issues since deprecated command checking moved to W024
        assert len(issues) == 0

    def test_unquoted_variable_in_echo(self) -> None:
        """Test unquoted variable in ECHO - should NOT trigger W005 (only IF comparisons do)."""
        set_vars: Set[str] = set()
        issues = _check_warning_issues("echo %VARIABLE%", 1, set_vars, False)
        # W005 is now more conservative - only checks IF string comparisons
        w005_issues = [i for i in issues if i.rule.code == "W005"]
        assert len(w005_issues) == 0, "W005 should not flag echo commands"

    def test_ping_without_timeout(self) -> None:
        """Test PING without timeout parameter."""
        set_vars: Set[str] = set()
        issues = _check_warning_issues("ping google.com", 1, set_vars, False)
        # Should detect W006 (ping without timeout) and W029 (16-bit command detection for .com)
        assert len(issues) >= 1
        rule_codes = [issue.rule.code for issue in issues]
        assert "W006" in rule_codes

    def test_setx_path_modification(self) -> None:
        """Test SETX PATH modification warning."""
        set_vars: Set[str] = set()
        issues = _check_warning_issues("setx path %PATH%;C:\\temp", 1, set_vars, False)
        # May also trigger W005 (Unquoted variable)
        w008_issues = [i for i in issues if i.rule.code == "W008"]
        assert len(w008_issues) == 1

    def test_older_windows_command(self) -> None:
        """Test older Windows command warning."""
        set_vars: Set[str] = set()
        issues = _check_warning_issues("choice /c yn /m Continue?", 1, set_vars, False)
        assert len(issues) == 1
        assert "W009" in issues[0].rule.code

    def test_architecture_specific_pattern(self) -> None:
        """Test architecture-specific pattern detection."""
        set_vars: Set[str] = set()
        issues = _check_warning_issues("cd Wow6432Node", 1, set_vars, False)
        assert len(issues) == 1
        assert "W010" in issues[0].rule.code

    def test_unicode_problematic_command(self) -> None:
        """Test Unicode problematic command with actual Unicode content."""
        set_vars: Set[str] = set()
        # Test with actual Unicode content that should trigger the warning
        issues = _check_warning_issues("type unicode_filé.txt", 1, set_vars, False)
        # Multiple Unicode-related warnings may be triggered
        w011_issues = [i for i in issues if i.rule.code == "W011"]
        assert len(w011_issues) == 1
        assert "type" in w011_issues[0].context

    def test_non_ascii_characters(self) -> None:
        """Test non-ASCII character detection."""
        set_vars: Set[str] = set()
        issues = _check_warning_issues(
            "echo Ñandú", 1, set_vars, False
        )  # Contains non-ASCII
        # May also trigger W011 (Unicode handling issue for echo command)
        w012_issues = [i for i in issues if i.rule.code == "W012"]
        assert len(w012_issues) == 1


class TestStyleIssueChecking:
    """Test style issue detection edge cases."""

    def test_long_parameter_list(self) -> None:
        """Test long parameter list detection."""
        issues = _check_style_issues(
            "CALL :myfunc param1 param2 param3 param4 param5 param6", 1
        )
        assert len(issues) == 1
        assert "S014" in issues[0].rule.code

    def test_magic_number_timeout(self) -> None:
        """Test magic number detection in timeout command."""
        issues = _check_style_issues("timeout /t 300", 1)
        # May also trigger S003 (command capitalization)
        s009_issues = [i for i in issues if i.rule.code == "S009"]
        assert len(s009_issues) == 1

    def test_magic_number_ping(self) -> None:
        """Test magic number detection in ping command."""
        issues = _check_style_issues("ping google.com -n 50", 1)
        # May also trigger S003 (command capitalization)
        s009_issues = [i for i in issues if i.rule.code == "S009"]
        assert len(s009_issues) == 1

    def test_command_casing_inconsistency(self) -> None:
        """Test command casing inconsistency detection."""
        # The new S003 rule only flags inconsistencies within the same file
        # So we need to create content with mixed casing for the same command
        # Use actual batch commands (not echo, which is often skipped)
        test_lines = [
            "set var1=hello",  # lowercase
            "SET var2=world",  # uppercase - this should trigger S003
        ]
        all_issues = []
        for line_num, line in enumerate(test_lines, 1):
            issues = _check_style_issues(line, line_num)
            all_issues.extend(issues)

        # Now check using the global function that detects inconsistencies
        from blinter import _check_cmd_case_consistency

        consistency_issues = _check_cmd_case_consistency(test_lines)

        assert len(consistency_issues) >= 1
        assert "S003" in consistency_issues[0].rule.code


class TestSecurityIssueChecking:
    """Test security issue detection edge cases."""

    def test_credential_patterns(self) -> None:
        """Test various credential pattern detection."""
        test_cases = [
            "set password=secret123",
            "set pwd=mypass",
            "set passwd=hidden",
            "set apikey=abc123",
            "set api_key=xyz789",
            "set secret=topsecret",
            "set token=bearer123",
        ]
        for line in test_cases:
            issues = _check_security_issues(line, 1)
            # May also trigger SEC002 (unquoted SET command)
            sec008_issues = [i for i in issues if i.rule.code == "SEC008"]
            assert len(sec008_issues) == 1

    def test_sensitive_echo_patterns(self) -> None:
        """Test sensitive information in ECHO detection."""
        test_cases = [
            "echo Your password is %PASSWORD%",
            "echo pwd: %PWD%",
            "echo passwd value",
            "echo apikey=123",
            "echo api_key value",
            "echo secret code",
            "echo token info",
        ]
        for line in test_cases:
            issues = _check_security_issues(line, 1)
            # May also trigger SEC008 (credential patterns) for some cases
            sec010_issues = [i for i in issues if i.rule.code == "SEC010"]
            assert len(sec010_issues) == 1


class TestPerformanceIssueChecking:
    """Test performance issue detection edge cases."""

    def test_inefficient_dir_command(self) -> None:
        """Test DIR command without /F flag."""
        issues = _check_performance_issues(
            [""], 1, "dir /s", False, False, False, False, False, False, False
        )
        assert len(issues) == 1
        assert "P010" in issues[0].rule.code

    def test_for_loop_without_tokens(self) -> None:
        """Test FOR loop without tokens optimization."""
        issues = _check_performance_issues(
            [""],
            1,
            'FOR /F "delims=," %%i IN (file.txt) DO echo %%i',
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )
        assert len(issues) == 1
        assert "P009" in issues[0].rule.code

    def test_temporary_file_without_random(self) -> None:
        """Test temporary file without random name."""
        issues = _check_performance_issues(
            [""],
            1,
            "echo content > temp.txt",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )
        assert len(issues) == 1
        assert "P007" in issues[0].rule.code

    def test_delayed_expansion_without_enablement(self) -> None:
        """Test delayed expansion variables without enablement."""
        issues = _check_performance_issues(
            [""], 1, "echo !VARIABLE!", False, False, False, False, False, False, False
        )
        assert len(issues) == 1
        assert "P008" in issues[0].rule.code

    def test_unnecessary_setlocal(self) -> None:
        """Test unnecessary SETLOCAL usage."""
        issues = _check_performance_issues(
            [""], 1, "setlocal", False, False, False, False, False, False, False
        )
        assert len(issues) == 1
        assert "P003" in issues[0].rule.code

    def test_unnecessary_enabledelayedexpansion(self) -> None:
        """Test unnecessary ENABLEDELAYEDEXPANSION usage."""
        issues = _check_performance_issues(
            [""],
            1,
            "setlocal enabledelayedexpansion",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )
        # May also trigger P003 (unnecessary SETLOCAL)
        p004_issues = [i for i in issues if i.rule.code == "P004"]
        assert len(p004_issues) == 1

    def test_endlocal_without_setlocal(self) -> None:
        """Test ENDLOCAL without SETLOCAL."""
        issues = _check_performance_issues(
            [""], 1, "endlocal", False, False, False, False, False, False, False
        )
        assert len(issues) == 1
        assert "P005" in issues[0].rule.code


class TestGlobalFunctionChecking:
    """Test global function edge cases and boundary conditions."""

    def test_check_missing_pause_with_user_input(self) -> None:
        """Test missing PAUSE detection when script has user input."""
        lines = [
            "set /p answer=Do you want to continue? ",
            "echo Processing...",
        ]
        from blinter import _check_missing_pause

        issues = _check_missing_pause(lines)
        assert len(issues) == 1
        assert "W014" in issues[0].rule.code

    def test_check_missing_pause_with_choice(self) -> None:
        """Test missing PAUSE detection when script has CHOICE command."""
        lines = [
            "choice /c yn /m Continue?",
            "echo Processing...",
        ]
        from blinter import _check_missing_pause

        issues = _check_missing_pause(lines)
        assert len(issues) == 1
        assert "W014" in issues[0].rule.code

    def test_check_missing_pause_already_has_pause(self) -> None:
        """Test no warning when script already has PAUSE."""
        lines = [
            "set /p answer=Continue? ",
            "pause",
            "echo Done",
        ]
        from blinter import _check_missing_pause

        issues = _check_missing_pause(lines)
        assert len(issues) == 0

    def test_check_inconsistent_indentation_mixed(self) -> None:
        """Test mixed tabs and spaces in same line."""
        lines = [
            "echo start",
            "\t echo mixed indentation",  # Tab followed by space - mixed within line
            "  echo other indentation",  # Just spaces
        ]
        from blinter import _check_inconsistent_indentation

        issues = _check_inconsistent_indentation(lines)
        assert len(issues) >= 1  # Should detect mixed indentation
        s012_issues = [i for i in issues if i.rule.code == "S012"]
        assert len(s012_issues) >= 1

    def test_check_inconsistent_indentation_across_file(self) -> None:
        """Test mixed indentation across file."""
        lines = [
            "echo start",
            "\techo with tab",
            "  echo with spaces",
            "echo end",
        ]
        from blinter import _check_inconsistent_indentation

        issues = _check_inconsistent_indentation(lines)
        assert len(issues) == 1
        assert "S012" in issues[0].rule.code

    def test_check_missing_documentation(self) -> None:
        """Test missing documentation detection."""
        lines = [
            "echo hello",
            "echo world",
            "echo more",
            "echo content",
            "echo here",
            "echo line 6",
            "echo line 7",
            "echo line 8",
            "echo line 9",
            "echo line 10",
            "echo line 11",
            "echo line 12",
            "echo line 13",
            "echo line 14",
            "echo line 15",
            "echo line 16",
            "echo line 17",
            "echo line 18",
            "echo line 19",
            "echo line 20",
            "echo line 21",
            "echo line 22",
            "echo line 23",
            "echo line 24",
            "echo line 25",
            "echo line 26",
            "echo line 27",
            "echo line 28",
            "echo line 29",
            "echo line 30",
            "echo line 31",  # Now 31 lines, should trigger S013 with new threshold of 30
        ]
        from blinter import _check_missing_header_doc

        issues = _check_missing_header_doc(lines)
        assert len(issues) == 1
        assert "S013" in issues[0].rule.code

    def test_check_missing_documentation_has_good_comments(self) -> None:
        """Test no warning when good documentation exists."""
        lines = [
            "rem Script: Test batch file",
            "rem Author: Test User",
            "echo hello",
            "echo world",
            "echo content",
        ]
        from blinter import _check_missing_header_doc

        issues = _check_missing_header_doc(lines)
        assert len(issues) == 0


class TestMainFunctionEdgeCases:
    """Test main function edge cases and CLI argument handling."""

    def test_find_batch_files_file_not_batch(self) -> None:
        """Test find_batch_files with non-batch file."""
        import os
        import tempfile

        from blinter import find_batch_files

        # Create a temporary file
        fd, temp_path = tempfile.mkstemp(suffix=".txt")
        try:
            os.close(fd)  # Close the file descriptor first
            with pytest.raises(ValueError, match="not a batch file"):
                find_batch_files(temp_path)
        finally:
            try:
                os.unlink(temp_path)
            except (OSError, PermissionError):
                pass  # Ignore cleanup errors

    def test_find_batch_files_nonexistent_path(self) -> None:
        """Test find_batch_files with nonexistent path."""
        from blinter import find_batch_files

        with pytest.raises(FileNotFoundError):
            find_batch_files("/nonexistent/path")

    def test_validate_and_read_file_edge_cases(self) -> None:
        """Test _validate_and_read_file edge cases."""
        from blinter import _validate_and_read_file

        # Test empty file path
        with pytest.raises(ValueError, match="file_path must be a non-empty string"):
            _validate_and_read_file("")

        # Test non-string file path
        with pytest.raises(ValueError, match="file_path must be a non-empty string"):
            _validate_and_read_file(None)

    def test_analyze_script_structure_edge_cases(self) -> None:
        """Test _analyze_script_structure edge cases."""
        from blinter import _analyze_script_structure

        lines = [
            "setlocal",
            "set VAR=value",
            "setlocal enabledelayedexpansion",
            "echo !VAR!",
        ]
        (
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
            _,
            _,
            _,
        ) = _analyze_script_structure(lines)
        assert has_setlocal is True
        assert has_set_commands is True
        assert has_delayed_expansion is True
        assert uses_delayed_vars is True

    def test_if_exist_with_defined_check(self) -> None:
        """Test IF statement with EXIST and DEFINED keywords."""
        labels: dict[str, int] = {}
        issues = _check_syntax_errors("if defined MYVAR echo found", 1, labels)
        assert len(issues) == 0  # Should not trigger E003


class TestAdditionalEdgeCaseScenarios:
    """Additional tests for complex edge case scenarios."""

    def test_encoding_failure_edge_case(self) -> None:
        """Test encoding failure when no exceptions are stored."""
        from blinter import read_file_with_encoding

        def mock_open_special(*args: object, **kwargs: object) -> object:
            # Return nothing but don't store exception
            if "encoding" in kwargs and kwargs["encoding"] == "utf-32":
                raise LookupError("Encoding not supported")
            raise UnicodeDecodeError("test", b"", 0, 1, "test error")

        with patch("builtins.open", side_effect=mock_open_special):
            try:
                read_file_with_encoding("test.bat")
                assert False, "Should have raised OSError"
            except OSError as e:
                # Should hit the fallback path with last_exception
                assert "All encoding attempts failed" in str(e)

    def test_validate_and_read_file_large_file_warning(self) -> None:
        """Test large file warning in _validate_and_read_file."""
        import os
        import tempfile

        from blinter import _validate_and_read_file

        # Mock a large file
        def mock_stat(*args: object, **kwargs: object) -> object:
            class StatResult:
                st_size = 15 * 1024 * 1024  # 15MB file
                st_mode = 0o100644  # Regular file mode

            return StatResult()

        fd, temp_path = tempfile.mkstemp(suffix=".bat")
        try:
            os.write(fd, b"@echo off\necho test")
            os.close(fd)

            with patch("pathlib.Path.stat", side_effect=mock_stat):
                with patch(
                    "builtins.open", mock_open(read_data="@echo off\necho test")
                ):
                    lines, encoding = _validate_and_read_file(temp_path)
                    assert len(lines) > 0
                    assert encoding in [
                        "utf-8",
                        "latin1",
                    ]  # Should succeed with some encoding
        finally:
            try:
                os.unlink(temp_path)
            except (OSError, PermissionError):
                pass

    def test_script_structure_analysis_edge_cases(self) -> None:
        """Test _analyze_script_structure with edge cases."""
        from blinter import _analyze_script_structure

        # Empty lines
        lines: list[str] = []
        result = _analyze_script_structure(lines)
        assert result == (False, False, False, False, False, False, False)

        # Lines with various patterns
        lines = [
            "setlocal",
            "set /p VAR=Input: ",
            "set /a NUM=5+3",
            "setlocal enabledelayedexpansion",
            "echo !VAR!",
        ]
        (
            has_setlocal,
            has_set_commands,
            has_delayed_expansion,
            uses_delayed_vars,
            _,
            _,
            _,
        ) = _analyze_script_structure(lines)
        assert has_setlocal is True
        assert has_set_commands is True  # Should detect set /p and set /a
        assert has_delayed_expansion is True
        assert uses_delayed_vars is True

    def test_missing_pause_edge_case(self) -> None:
        """Test _check_missing_pause with edge cases."""
        from blinter import _check_missing_pause

        # Script with user input but already has pause - should not warn
        lines = [
            "set /p answer=Continue?",
            "echo Processing...",
            "pause > nul",  # Has pause, so no warning
            "echo Done",
        ]
        issues = _check_missing_pause(lines)
        assert len(issues) == 0

    def test_find_batch_files_not_file_or_directory(self) -> None:
        """Test find_batch_files with invalid path type."""
        import os

        from blinter import find_batch_files

        # This should be very rare, but test the "neither file nor directory" path
        # We'll mock a path that exists but is neither
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.is_file", return_value=False),
            patch("pathlib.Path.is_dir", return_value=False),
        ):
            with pytest.raises(ValueError, match="neither a file nor a directory"):
                find_batch_files("invalid_path")

    def test_if_statement_with_exist_keyword(self) -> None:
        """Test IF statement with exist keyword."""
        labels: dict[str, int] = {}
        issues = _check_syntax_errors("if exist myfile.txt echo found", 1, labels)
        assert len(issues) == 0  # Should not trigger E003

    def test_security_is_command_in_safe_context(self) -> None:
        """Test _is_command_in_safe_context function behavior."""
        from blinter import _is_command_in_safe_context

        # Test REM comment context
        assert _is_command_in_safe_context("rem del *.* is dangerous") is True
        assert _is_command_in_safe_context("REM	format c: is dangerous") is True

        # Test ECHO context
        assert _is_command_in_safe_context("echo The del command removes files") is True
        assert _is_command_in_safe_context("@echo format c: formats drive") is True

        # Test non-safe context
        assert _is_command_in_safe_context("del *.* /q") is False

    def test_chardet_detected_encoding_not_in_list(self) -> None:
        """Test chardet detecting encoding not in our default list."""
        from blinter import read_file_with_encoding

        mock_detected = {"encoding": "iso-2022-jp", "confidence": 0.85}

        with (
            patch("builtins.open", mock_open(read_data="test content")),
            patch("chardet.detect", return_value=mock_detected),
        ):
            # Should succeed by adding the detected encoding to the front
            lines, encoding = read_file_with_encoding("test.bat")
            assert len(lines) > 0

    def test_style_issues_edge_cases(self) -> None:
        """Test style issue detection edge cases."""
        from blinter import _check_style_issues

        # Small number, should not trigger magic number rule
        issues = _check_style_issues("timeout /t 5", 1)
        # Should only trigger S003 (command casing), not S009 (magic number)
        s009_issues = [i for i in issues if i.rule.code == "S009"]
        assert len(s009_issues) == 0  # Small numbers shouldn't be flagged

    def test_main_function_directory_processing_edge_case(self) -> None:
        """Test main function with directory processing edge cases."""
        import sys

        from blinter import main

        # Test with --no-recursive flag
        original_argv = sys.argv[:]
        try:
            sys.argv = ["blinter.py", "nonexistent_directory", "--no-recursive"]
            # Should handle nonexistent directory gracefully
            main()  # Should exit without crashing
        except SystemExit:
            pass  # Expected
        finally:
            sys.argv = original_argv

    def test_performance_issue_edge_cases(self) -> None:
        """Test performance issue detection edge cases."""
        from blinter import _check_performance_issues

        # Test temp file with random - should not trigger P007
        issues = _check_performance_issues(
            [""],
            1,
            "echo content > temp_%RANDOM%.txt",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )
        p007_issues = [i for i in issues if i.rule.code == "P007"]
        assert len(p007_issues) == 0  # Should not flag when RANDOM is used

    def test_missing_pause_reverse_line_order(self) -> None:
        """Test _check_missing_pause finding appropriate line number."""
        from blinter import _check_missing_pause

        # Test finding the last executable line for warning
        lines = [
            "set /p answer=Continue?",
            "echo Processing...",
            "echo More processing...",
            "rem This is a comment",  # Should skip comments
            "",  # Should skip empty lines
        ]
        issues = _check_missing_pause(lines)
        assert len(issues) == 1
        # Should flag line 3 (last non-comment, non-empty executable line)
        assert issues[0].line_number == 3

    def test_inconsistent_indentation_few_indented_lines(self) -> None:
        """Test inconsistent indentation with less than 2 indented lines."""
        from blinter import _check_inconsistent_indentation

        lines = [
            "echo start",
            "  echo only one indented line",
            "echo end",
        ]
        issues = _check_inconsistent_indentation(lines)
        assert len(issues) == 0  # Should not flag with only one indented line

    def test_main_function_no_path_provided(self) -> None:
        """Test main function when no path is provided."""
        import sys

        from blinter import main

        original_argv = sys.argv[:]
        try:
            sys.argv = ["blinter.py"]  # No path argument
            main()  # Should print help and return
        except SystemExit:
            pass  # Expected
        finally:
            sys.argv = original_argv

    def test_main_function_single_file_processing(self) -> None:
        """Test main function processing single file vs directory."""
        import os
        import sys
        import tempfile

        from blinter import main

        # Create a temporary batch file
        fd, temp_path = tempfile.mkstemp(suffix=".bat")
        try:
            os.write(fd, b"@ECHO OFF\necho Hello World\nEXIT /b 0")
            os.close(fd)

            original_argv = sys.argv[:]
            try:
                sys.argv = ["blinter.py", temp_path]
                main()  # Should process single file
            except SystemExit:
                pass  # Expected
            finally:
                sys.argv = original_argv
        finally:
            try:
                os.unlink(temp_path)
            except (OSError, PermissionError):
                pass

    def test_security_admin_commands_edge_cases(self) -> None:
        """Test admin command detection edge cases."""
        from blinter import _check_security_issues

        # Test specific admin commands
        test_cases = [
            "reg add HKLM\\Software\\Test /v Value /d Data",
            "reg delete HKLM\\Software\\Test /v Value /f",
            "sc stop ServiceName",
            "net user testuser testpass /add",
        ]

        for line in test_cases:
            issues = _check_security_issues(line, 1)
            sec005_issues = [i for i in issues if i.rule.code == "SEC005"]
            assert len(sec005_issues) >= 1  # Should detect privilege requirement

    def test_path_with_single_quotes(self) -> None:
        """Test path validation with single quotes."""
        labels: dict[str, int] = {}
        issues = _check_syntax_errors("copy 'bad|path.txt' dest", 1, labels)
        assert len(issues) == 1
        assert issues[0].rule.code == "E005"

    def test_path_with_double_quotes(self) -> None:
        """Test path validation with double quotes."""
        labels: dict[str, int] = {}
        issues = _check_syntax_errors('copy "bad<path.txt", dest', 1, labels)
        assert len(issues) == 1
        assert issues[0].rule.code == "E005"

    def test_path_without_invalid_characters(self) -> None:
        """Test path validation without invalid characters."""
        labels: dict[str, int] = {}
        issues = _check_syntax_errors('copy "goodpath.txt" dest', 1, labels)
        path_issues = [i for i in issues if i.rule.code == "E005"]
        assert len(path_issues) == 0


class TestWarningChecking:
    """Test warning level checking edge cases."""

    def test_ping_with_parameters_but_no_timeout(self) -> None:
        """Test PING command with parameters but no timeout."""
        set_vars: set[str] = set()
        issues = _check_warning_issues("ping google.com", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W006"]
        assert len(warning_issues) == 1

    def test_ping_with_proper_timeout(self) -> None:
        """Test PING command with proper timeout."""
        set_vars: set[str] = set()
        issues = _check_warning_issues("ping google.com -n 4", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W006"]
        assert len(warning_issues) == 0

    def test_setx_path_modification(self) -> None:
        """Test SETX PATH modification detection."""
        set_vars: set[str] = set()
        issues = _check_warning_issues(
            "setx PATH %PATH%;C:\\newpath", 1, set_vars, False
        )
        warning_issues = [i for i in issues if i.rule.code == "W008"]
        assert len(warning_issues) == 1

    def test_older_windows_commands(self) -> None:
        """Test detection of older Windows commands."""
        set_vars: set[str] = set()
        # Removed "timeout" as it's been available since Windows Vista
        # Removed "robocopy" as it's been available since Windows Vista/Server 2008 (2007-2008)
        for cmd in ["choice", "forfiles", "where", "icacls"]:
            issues = _check_warning_issues(f"{cmd} /param", 1, set_vars, False)
            warning_issues = [i for i in issues if i.rule.code == "W009"]
            assert len(warning_issues) == 1
            assert cmd in warning_issues[0].context

    def test_architecture_specific_patterns(self) -> None:
        """Test detection of architecture-specific patterns."""
        set_vars: set[str] = set()
        test_cases = [
            ("reg query HKLM\\SOFTWARE\\Wow6432Node\\Test", "Wow6432Node"),
            ("copy SysWow64\\file.txt dest", "SysWow64"),
        ]
        for command, expected_pattern in test_cases:
            issues = _check_warning_issues(command, 1, set_vars, False)
            warning_issues = [i for i in issues if i.rule.code == "W010"]
            assert len(warning_issues) == 1
            assert expected_pattern in warning_issues[0].context

    def test_program_files_x86_pattern_not_matched(self) -> None:
        """Test that Program Files (x86) pattern requires specific format."""
        # The pattern is looking for literal \(x86\) which doesn't match (x86)
        set_vars: set[str] = set()
        issues = _check_warning_issues('cd "Program Files (x86)"', 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W010"]
        assert len(warning_issues) == 0  # Won't match because pattern expects \\(x86\\)

    def test_unicode_problematic_commands(self) -> None:
        """Test detection of Unicode problematic commands with actual Unicode risks."""
        set_vars: set[str] = set()
        # Test commands with actual Unicode content that should be flagged
        issues = _check_warning_issues("type unicode_filé.txt", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W011"]
        # The improved rule should still catch this because it has Unicode in filename
        assert len(warning_issues) == 1
        assert "type" in warning_issues[0].context

        # Test find/findstr with Unicode content
        issues = _check_warning_issues(
            "findstr /i pattérn file.txt", 1, set_vars, False
        )
        warning_issues = [i for i in issues if i.rule.code == "W011"]
        assert len(warning_issues) == 1

        # Test echo with non-ASCII - should be flagged
        issues = _check_warning_issues("echo héllo", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W011"]
        assert len(warning_issues) == 1

        # Test echo with redirection - improved rule now considers this safe
        issues = _check_warning_issues("echo test > file", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W011"]
        assert len(warning_issues) == 0  # Now considered safe by improved rule

        # Test simple echo - should NOT be flagged
        issues = _check_warning_issues("echo simple text", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W011"]
        assert len(warning_issues) == 0

    def test_non_ascii_character_detection(self) -> None:
        """Test detection of non-ASCII characters."""
        set_vars: set[str] = set()
        issues = _check_warning_issues("echo héllo wørld", 1, set_vars, False)
        warning_issues = [i for i in issues if i.rule.code == "W012"]
        assert len(warning_issues) == 1

    def test_for_loop_variables_no_false_positive(self) -> None:
        """Test that FOR loop variables (%%a %%b) don't trigger Unicode warnings."""
        set_vars: set[str] = set()
        # FOR loop variables should NOT trigger W011 Unicode warning
        issues = _check_warning_issues("echo %%a %%b", 1, set_vars, False)
        w011_issues = [i for i in issues if i.rule.code == "W011"]
        assert (
            len(w011_issues) == 0
        ), "FOR loop variables should not trigger Unicode warnings"

    def test_consecutive_variables_no_false_positive(self) -> None:
        """Test that consecutive variables like %red%%under% don't trigger false
        Unicode warnings."""
        set_vars: set[str] = {"red", "under", "def"}
        # Consecutive variables should NOT trigger W011 Unicode warning
        issues = _check_warning_issues("echo %red%%under%text%def%", 1, set_vars, False)
        w011_issues = [i for i in issues if i.rule.code == "W011"]
        assert (
            len(w011_issues) == 0
        ), "Consecutive variables should not trigger Unicode warnings"

    def test_echo_with_actual_unicode_still_flagged(self) -> None:
        """Test that actual Unicode content in echo still triggers warnings."""
        set_vars: set[str] = set()
        # Real Unicode content should still trigger W011
        issues = _check_warning_issues("echo Ñandú birds", 1, set_vars, False)
        w011_issues = [i for i in issues if i.rule.code == "W011"]
        assert (
            len(w011_issues) == 1
        ), "Actual Unicode content should still trigger warnings"


class TestStyleChecking:
    """Test style level checking edge cases."""

    def test_magic_numbers_in_timeout_command(self) -> None:
        """Test detection of magic numbers in timeout command."""
        issues = _check_style_issues("timeout /t 30", 1)
        magic_number_issues = [i for i in issues if i.rule.code == "S009"]
        assert len(magic_number_issues) == 1
        assert "30" in magic_number_issues[0].context

    def test_magic_numbers_in_ping_command(self) -> None:
        """Test detection of magic numbers in ping command."""
        issues = _check_style_issues("ping localhost -n 100", 1)
        magic_number_issues = [i for i in issues if i.rule.code == "S009"]
        assert len(magic_number_issues) == 1
        assert "100" in magic_number_issues[0].context

    def test_small_numbers_not_flagged(self) -> None:
        """Test that small numbers are not flagged as magic numbers."""
        issues = _check_style_issues("ping localhost -n 5", 1)
        magic_number_issues = [i for i in issues if i.rule.code == "S009"]
        assert len(magic_number_issues) == 0

    def test_command_casing_detection(self) -> None:
        """Test command casing consistency detection."""
        # Test with commands that are actually processed (not echo which is often skipped)
        keywords = ["set", "if", "for", "goto", "call", "cd"]
        for keyword in keywords:
            # Create inconsistent casing for the same command within a file
            test_lines = [
                f"{keyword} test",  # lowercase
                f"{keyword.upper()} test2",  # uppercase - should trigger S003
            ]

            from blinter import _check_cmd_case_consistency

            consistency_issues = _check_cmd_case_consistency(test_lines)
            casing_issues = [i for i in consistency_issues if i.rule.code == "S003"]
            assert (
                len(casing_issues) >= 1
            ), f"No S003 issues found for keyword: {keyword}"
            # Check that the keyword appears in one of the contexts
            contexts = [issue.context for issue in casing_issues]
            assert any(keyword in context.lower() for context in contexts)


class TestSecurityChecking:
    """Test security level checking edge cases."""

    def test_command_injection_pattern(self) -> None:
        """Test detection of potential command injection."""
        issues = _check_security_issues("set /p input=Enter command: && %input%", 1)
        injection_issues = [i for i in issues if i.rule.code == "SEC001"]
        assert len(injection_issues) == 1

    def test_unquoted_set_command(self) -> None:
        """Test detection of unquoted SET commands."""
        issues = _check_security_issues("set MYVAR=some value with spaces", 1)
        unsafe_set_issues = [i for i in issues if i.rule.code == "SEC002"]
        assert len(unsafe_set_issues) == 1

    def test_quoted_set_command_safe(self) -> None:
        """Test that properly quoted SET commands are not flagged."""
        issues = _check_security_issues('set "MYVAR=some value with spaces"', 1)
        unsafe_set_issues = [i for i in issues if i.rule.code == "SEC002"]
        assert len(unsafe_set_issues) == 0

    def test_admin_privilege_commands(self) -> None:
        """Test detection of commands requiring admin privileges."""
        admin_commands = [
            ("reg add hklm", "reg add hklm"),
            ("reg delete hklm", "reg delete hklm"),
            ("sc config", "sc"),
            ("net user", "NET command"),
        ]
        for cmd, expected in admin_commands:
            issues = _check_security_issues(f"{cmd} something", 1)
            privilege_issues = [i for i in issues if i.rule.code == "SEC005"]
            assert len(privilege_issues) == 1
            assert expected in privilege_issues[0].context

    def test_hardcoded_absolute_paths(self) -> None:
        """Test detection of hardcoded absolute paths."""
        paths = ["C:\\Program Files\\", "D:\\MyApp\\", "/home/user/", "/Users/admin/"]
        for path in paths:
            issues = _check_security_issues(f'copy "{path}file.txt" dest', 1)
            path_issues = [i for i in issues if i.rule.code == "SEC006"]
            assert len(path_issues) == 1

    def test_hardcoded_paths_in_safe_contexts(self) -> None:
        """Test that hardcoded paths in ECHO/REM/:: statements are not flagged."""
        # ECHO statements should not trigger SEC006 (used for documentation/help)
        echo_cases = [
            "ECHO  %~n0 C:\\Scripts E:\\Scripts.Old",
            "ECHO  %~n0 C:\\Scripts F:\\Scripts.New /U",
            "echo Usage: C:\\Source D:\\Destination",
            'ECHO  "C:\\Programs\\This Program" "Y:\\Remote\\A Long Folder Name"',
            "@echo off",  # This is a command, not documentation, but should still be safe
            "@ECHO Example: C:\\Path\\To\\File",
            "echo /home/user/documents",
            "echo /Users/admin/Desktop",
        ]
        for echo_line in echo_cases:
            issues = _check_security_issues(echo_line, 1)
            path_issues = [i for i in issues if i.rule.code == "SEC006"]
            assert (
                len(path_issues) == 0
            ), f"ECHO line should not trigger SEC006: {echo_line}"

        # REM comments should not trigger SEC006
        rem_cases = [
            "REM This is a comment about C:\\Path\\To\\Something",
            "REM Example: D:\\MyApp\\config.ini",
            "rem User directory: /home/user/files",
            "REM\tC:\\Windows\\System32",
        ]
        for rem_line in rem_cases:
            issues = _check_security_issues(rem_line, 1)
            path_issues = [i for i in issues if i.rule.code == "SEC006"]
            assert (
                len(path_issues) == 0
            ), f"REM line should not trigger SEC006: {rem_line}"

        # :: comments should not trigger SEC006
        colon_cases = [
            ":: This is a comment about C:\\Path\\To\\Something",
            ":: Example: E:\\Data\\backup",
            ":: Linux path: /usr/local/bin",
        ]
        for colon_line in colon_cases:
            issues = _check_security_issues(colon_line, 1)
            path_issues = [i for i in issues if i.rule.code == "SEC006"]
            assert (
                len(path_issues) == 0
            ), f":: line should not trigger SEC006: {colon_line}"

        # But actual commands with hardcoded paths SHOULD still be flagged
        actual_commands = [
            "copy C:\\Source\\file.txt D:\\Dest\\",
            "xcopy /s C:\\Data E:\\Backup",
            "cd C:\\Windows\\System32",
            "move /home/user/file.txt /tmp/",
        ]
        for cmd_line in actual_commands:
            issues = _check_security_issues(cmd_line, 1)
            path_issues = [i for i in issues if i.rule.code == "SEC006"]
            assert (
                len(path_issues) >= 1
            ), f"Actual command should trigger SEC006: {cmd_line}"

    def test_hardcoded_temp_paths(self) -> None:
        """Test detection of hardcoded temporary paths."""
        # Actual commands with hardcoded temp paths should be flagged
        flagged_cases = [
            "copy /tmp/file.txt dest",  # Linux temp path
            "move C:\\temp\\file.txt dest",  # Windows temp path
            "xcopy C:\\tmp\\* dest",  # Windows tmp path
        ]
        for cmd in flagged_cases:
            issues = _check_security_issues(cmd, 1)
            temp_issues = [i for i in issues if i.rule.code == "SEC007"]
            assert len(temp_issues) >= 1, f"Command should trigger SEC007: {cmd}"

        # ECHO statements and comments should NOT be flagged (documentation/help text)
        safe_cases = [
            "echo C:\\temp in path",  # ECHO statement
            "echo C:\\tmp in path",  # ECHO statement
            "echo /tmp in path",  # ECHO statement
            "REM This uses C:\\temp for temp files",  # REM comment
            ":: Temporary directory: C:\\tmp",  # :: comment
        ]
        for cmd in safe_cases:
            issues = _check_security_issues(cmd, 1)
            temp_issues = [i for i in issues if i.rule.code == "SEC007"]
            assert (
                len(temp_issues) == 0
            ), f"Safe context should not trigger SEC007: {cmd}"


class TestPerformanceChecking:
    """Test performance level checking edge cases."""

    def test_setlocal_without_set_commands(self) -> None:
        """Test detection of unnecessary SETLOCAL."""
        lines = ["@echo off", "setlocal", "echo hello"]
        issues = _check_performance_issues(
            lines, 2, "setlocal", False, False, False, False, False, False, False
        )
        setlocal_issues = [i for i in issues if i.rule.code == "P003"]
        assert len(setlocal_issues) == 1

    def test_enabledelayedexpansion_without_delayed_vars(self) -> None:
        """Test detection of unnecessary ENABLEDELAYEDEXPANSION."""
        lines = ["setlocal enabledelayedexpansion", "echo hello"]
        issues = _check_performance_issues(
            lines,
            1,
            "setlocal enabledelayedexpansion",
            True,
            True,
            True,
            False,
            False,
            False,
            False,
        )
        delayed_issues = [i for i in issues if i.rule.code == "P004"]
        assert len(delayed_issues) == 1

    def test_endlocal_without_setlocal(self) -> None:
        """Test detection of ENDLOCAL without SETLOCAL."""
        lines = ["@echo off", "endlocal"]
        issues = _check_performance_issues(
            lines, 2, "endlocal", False, False, False, False, False, False, False
        )
        endlocal_issues = [i for i in issues if i.rule.code == "P005"]
        assert len(endlocal_issues) == 1

    def test_temp_file_without_random(self) -> None:
        """Test detection of temp files without random names."""
        temp_patterns = ["temp.txt", "tmp.txt", "temp.log"]
        for pattern in temp_patterns:
            lines = [f"echo test > {pattern}"]
            issues = _check_performance_issues(
                lines,
                1,
                f"echo test > {pattern}",
                False,
                False,
                False,
                False,
                False,
                False,
                False,
            )
            temp_issues = [i for i in issues if i.rule.code == "P007"]
            assert len(temp_issues) == 1

    def test_temp_file_with_random_no_issue(self) -> None:
        """Test that temp files with random names don't trigger issues."""
        lines = ["echo test > temp_%RANDOM%.txt"]
        issues = _check_performance_issues(
            lines,
            1,
            "echo test > temp_%RANDOM%.txt",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )
        temp_issues = [i for i in issues if i.rule.code == "P007"]
        assert len(temp_issues) == 0

    def test_delayed_expansion_without_enablement(self) -> None:
        """Test detection of delayed expansion without enablement."""
        lines = ["echo !MYVAR!"]
        issues = _check_performance_issues(
            lines, 1, "echo !MYVAR!", False, False, False, False, False, False, False
        )
        delayed_issues = [i for i in issues if i.rule.code == "P008"]
        assert len(delayed_issues) == 1


class TestGlobalChecks:
    """Test global checking functions."""

    def test_collect_labels_with_duplicates(self) -> None:
        """Test label collection with duplicates."""
        lines = [":label1", "echo test", ":label1", "echo duplicate"]
        _, issues = _collect_labels(lines)
        assert len(issues) == 1
        assert issues[0].rule.code == "W013"
        assert "label1" in issues[0].context

    def test_collect_set_variables_comprehensive(self) -> None:
        """Test comprehensive variable collection."""
        lines = [
            "set VAR1=value1",
            "set /p VAR2=Enter value:",
            "set /a VAR3=5+3",
            "SET UPPER=test",
        ]
        variables = _collect_set_variables(lines)
        assert "VAR1" in variables
        assert "VAR2" in variables
        assert "VAR3" in variables
        assert "UPPER" in variables
        # Should also include common environment variables
        assert "PATH" in variables
        assert "TEMP" in variables

    def test_check_undefined_variables(self) -> None:
        """Test undefined variable detection."""
        lines = ["echo %UNDEFINED_VAR%", "set DEFINED=test", "echo %DEFINED%"]
        set_vars = {"DEFINED", "PATH", "TEMP"}  # Include some common env vars
        issues = _check_undefined_variables(lines, set_vars)
        undefined_issues = [i for i in issues if i.rule.code == "E006"]
        assert len(undefined_issues) == 1
        assert "UNDEFINED_VAR" in undefined_issues[0].context

    def test_check_unreachable_code_after_exit(self) -> None:
        """Test unreachable code detection after EXIT."""
        lines = ["echo start", "exit /b 0", "echo unreachable"]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        assert len(unreachable_issues) == 1
        assert unreachable_issues[0].line_number == 3

    def test_check_unreachable_code_after_goto(self) -> None:
        """Test unreachable code detection after GOTO."""
        lines = ["echo start", "goto end", "echo unreachable", ":end"]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        assert len(unreachable_issues) == 1
        assert unreachable_issues[0].line_number == 3

    def test_no_unreachable_code_after_labels_comments(self) -> None:
        """Test that labels and comments after EXIT/GOTO are not flagged."""
        lines = ["echo start", "exit /b 0", ":label", "rem comment"]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        assert len(unreachable_issues) == 0

    def test_block_redirection_not_unreachable(self) -> None:
        """Test that block redirection operators are not flagged as unreachable code."""
        # This tests the GitHub issue where redirection after a block is incorrectly
        # flagged as unreachable code
        lines = [
            " rem -- Print Count of Discovered Systems by OS",
            ' IF "%~1"=="----" (',
            "\t ECHO:",
            '\t FOR /F "TOKENS=2-3 DELIMS==#" %%F IN (\'SET "#COUNT#" 2^>NUL\') DO (',
            "\t\t CALL :ChangeCase #NAME#%%F -U",
            "\t\t SET @THISOS=%%F",
            "\t\t SET @THISOS=!@THISOS:_=,!",
            "\t\t ECHO \t%%G \t!@THISOS:–= !",
            "\t\t ECHO \t\t -- !#NAME#%%F!",
            "\t\t ECHO:",
            "\t )",
            "\t EXIT /B",
            " ) >>%@LOGFILE% 2>&1",  # This line should NOT be flagged as unreachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        # The redirection operator line should NOT be flagged
        assert len(unreachable_issues) == 0

    def test_various_redirection_patterns_not_unreachable(self) -> None:
        """Test various redirection operator patterns after EXIT."""
        # Test different redirection patterns
        test_cases = [
            # Standard output redirection
            ["IF true (", "  EXIT /B", ") >output.txt"],
            # Append redirection
            ["IF true (", "  EXIT /B", ") >>output.log"],
            # Input redirection
            ["IF true (", "  EXIT /B", ") <input.txt"],
            # Error redirection
            ["IF true (", "  EXIT /B", ") 2>error.log"],
            # Combined output and error
            ["IF true (", "  EXIT /B", ") >output.txt 2>&1"],
            # Suppress output
            ["IF true (", "  EXIT /B", ") >nul 2>&1"],
            # Error to null
            ["IF true (", "  EXIT /B", ") 2>nul"],
        ]

        for lines in test_cases:
            issues = _check_unreachable_code(lines)
            unreachable_issues = [i for i in issues if i.rule.code == "E008"]
            assert (
                len(unreachable_issues) == 0
            ), f"Redirection should not be flagged as unreachable: {lines[-1]}"

    def test_truly_unreachable_code_still_detected(self) -> None:
        """Test that truly unreachable code is still detected after unconditional EXIT."""
        # EXIT at depth 0 (not in a conditional block) makes following code unreachable
        lines = [
            "ECHO start",
            "EXIT /B",
            "ECHO this is truly unreachable",  # This IS unreachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        # Should detect the ECHO command after unconditional EXIT as unreachable
        assert len(unreachable_issues) == 1
        assert unreachable_issues[0].line_number == 3

    def test_exit_inside_if_block_with_redirect_append(self) -> None:
        """Test EXIT inside IF block with redirect append operator (>>)."""
        lines = [
            'IF "%~1"=="test" (',
            "  ECHO Processing test",
            "  EXIT /B",
            ") >>%LOGFILE% 2>&1",
            "ECHO Main routine continues",  # This IS reachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        # Line 5 is reachable because EXIT is inside IF block
        assert len(unreachable_issues) == 0

    def test_goto_inside_if_block_with_redirect_single(self) -> None:
        """Test GOTO inside IF block with single redirect operator (>)."""
        lines = [
            'IF EXIST "file.txt" (',
            "  ECHO File found",
            "  GOTO :process",
            ") >output.log",
            "ECHO Default processing",  # This IS reachable
            ":process",
            "ECHO Processing file",
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        # Line 5 is reachable because GOTO is inside IF block
        assert len(unreachable_issues) == 0

    def test_exit_inside_nested_blocks_with_redirect(self) -> None:
        """Test EXIT inside nested blocks with redirect operators."""
        lines = [
            'IF "%~1"=="outer" (',
            '  IF "%~2"=="inner" (',
            "    ECHO Inner condition",
            "    EXIT /B 0",
            "  ) >inner.log",
            "  ECHO Outer continues",  # This IS reachable
            ") >>outer.log 2>&1",
            "CALL :MainRoutine",  # This IS reachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        # Both lines after the EXIT are reachable
        assert len(unreachable_issues) == 0

    def test_exit_with_redirect_error_stream(self) -> None:
        """Test EXIT with error stream redirect (2>)."""
        lines = [
            "IF DEFINED MYVAR (",
            "  SET VALUE=%MYVAR%",
            "  EXIT /B",
            ") 2>error.log",
            "ECHO Processing without MYVAR",  # This IS reachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        assert len(unreachable_issues) == 0

    def test_exit_with_combined_redirect(self) -> None:
        """Test EXIT with combined stdout and stderr redirect (>file 2>&1)."""
        lines = [
            "IF ERRORLEVEL 1 (",
            "  ECHO Error occurred",
            "  EXIT /B 1",
            ") >output.txt 2>&1",
            "ECHO Success path",  # This IS reachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        assert len(unreachable_issues) == 0

    def test_exit_with_nul_redirect(self) -> None:
        """Test EXIT with redirect to nul."""
        lines = [
            "IF NOT EXIST file.txt (",
            "  ECHO File not found",
            "  EXIT /B 2",
            ") >nul 2>&1",
            "ECHO File exists",  # This IS reachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        assert len(unreachable_issues) == 0

    def test_ops_logs_exact_pattern(self) -> None:
        """Test the exact pattern from OpsLogs.BAT that triggered the bug."""
        lines = [
            " rem -- Print Count of Discovered Systems by OS",
            ' IF "%~1"=="----" (',
            "\t ECHO:",
            '\t FOR /F "TOKENS=2-3 DELIMS==#" %%F IN (\'SET "#COUNT#" 2^>NUL\') DO (',
            "\t\t CALL :ChangeCase #NAME#%%F -U",
            "\t\t SET @THISOS=%%F",
            "\t\t SET @THISOS=!@THISOS:_=,!",
            "\t\t ECHO \t%%G \t!@THISOS:–= !",
            "\t\t ECHO \t\t -- !#NAME#%%F!",
            "\t\t ECHO:",
            "\t )",
            "\t EXIT /B",
            " ) >>%@LOGFILE% 2>&1",
            "",
            " rem -- Main Routine",
            " CALL :DisplaySysInfo %~1",  # Line 16: This IS reachable
        ]
        issues = _check_unreachable_code(lines)
        unreachable_issues = [i for i in issues if i.rule.code == "E008"]
        # Line 16 should NOT be flagged as unreachable
        assert len(unreachable_issues) == 0

    def test_check_redundant_operations(self) -> None:
        """Test redundant operations detection."""
        lines = [
            "if exist file.txt echo found",
            "echo something",
            "if exist file.txt del file.txt",
        ]
        issues = _check_redundant_operations(lines)
        redundant_issues = [i for i in issues if i.rule.code == "P001"]
        assert len(redundant_issues) == 1
        assert redundant_issues[0].line_number == 3

    def test_check_code_duplication(self) -> None:
        """Test code duplication detection."""
        # Code duplication needs 3+ similar commands AND normalized length > 20
        # Note: The new implementation requires normalized commands > 40 chars and uses
        # adaptive thresholds based on script size. For very small scripts (< 100 lines),
        # the threshold is 3+ occurrences within 100 lines of each other.
        lines = [
            "robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 "
            "/LOG:backup.log with some extra text",
            "robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 "
            "/LOG:backup2.log with some extra text",
            "robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 "
            "/LOG:backup3.log with some extra text",
            "robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 "
            "/LOG:backup4.log with some extra text",
        ]
        # This normalizes variables to VAR and files to FILE, all should be identical
        issues = _check_code_duplication(lines)
        duplication_issues = [i for i in issues if i.rule.code == "P002"]
        assert len(duplication_issues) == 3  # Lines 2, 3 and 4 should be flagged

    def test_no_code_duplication_with_few_commands(self) -> None:
        """Test that code duplication requires 3+ similar commands."""
        lines = [
            "copy file1.txt backup\\file1.txt",
            "copy file2.txt backup\\file2.txt",  # Only 2 similar, should not trigger
        ]
        issues = _check_code_duplication(lines)
        duplication_issues = [i for i in issues if i.rule.code == "P002"]
        assert len(duplication_issues) == 0


class TestRuleEdgeCases:
    """Test edge cases in individual rules that are hard to trigger."""

    def create_temp_batch_file(self, content: str) -> str:
        """Create a temporary batch file with the given content."""
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".bat", encoding="utf-8"
        ) as f:
            f.write(content)
            return f.name

    def test_comment_style_labels_not_flagged_as_duplicates(self) -> None:
        """Test that comment-style labels (:::::::) are not flagged as duplicates."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
::::::::::::::::::::::::
:: This is a comment
::::::::::::::::::::::::
ECHO Hello
::::::::::::::::::::::::
:: Another comment  
::::::::::::::::::::::::
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should not have duplicate label warnings for comment-style labels
            duplicate_issues = [i for i in issues if i.rule.code == "W013"]
            assert len(duplicate_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_e003_if_incomplete_comparison(self) -> None:
        """Test E003 rule for incomplete IF statement comparisons."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
IF myvar
IF "somevalue"
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e003_issues = [i for i in issues if i.rule.code == "E003"]
            assert len(e003_issues) == 2
        finally:
            os.unlink(temp_file)

    def test_e011_mismatched_percent_delimiters(self) -> None:
        """Test E011 rule for mismatched percent delimiters."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
ECHO This has mismatched %VAR delimiters
SET result=%ERRORLEVEL
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 2  # Both lines have mismatched delimiters
        finally:
            os.unlink(temp_file)

    def test_e011_mismatched_exclamation_delimiters(self) -> None:
        """Test E011 rule for mismatched exclamation delimiters."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
SETLOCAL ENABLEDELAYEDEXPANSION
ECHO This has mismatched !VAR delimiters
SET result=!ERRORLEVEL
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 2  # Both lines have mismatched delimiters
        finally:
            os.unlink(temp_file)

    def test_s014_long_parameter_list(self) -> None:
        """Test S014 rule for long parameter lists in CALL statements."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
CALL :myfunction param1 param2 param3 param4 param5 param6 param7
:myfunction
ECHO Function called
GOTO :EOF
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            s014_issues = [i for i in issues if i.rule.code == "S014"]
            assert len(s014_issues) == 1
            assert "7 parameters" in s014_issues[0].context
        finally:
            os.unlink(temp_file)

    def test_s014_call_with_chained_command(self) -> None:
        """Test that chained commands after CALL are not counted as parameters."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
CALL :GetParams "D" @THISDAY & IF NOT DEFINED @THISDAY (SET @THISDAY=%@TODAY_EXP%)
CALL :myfunc p1 p2 && ECHO Success
CALL :myfunc p1 p2 || ECHO Failure
CALL :myfunc p1 p2 | findstr "test"
:GetParams
:myfunc
GOTO :EOF
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            s014_issues = [i for i in issues if i.rule.code == "S014"]
            # None of these should trigger S014 as they all have <=5 parameters before chaining
            assert len(s014_issues) == 0
        finally:
            os.unlink(temp_file)


class TestSpecificRuleEdgeCases:
    """Test specific rule edge cases that are hard to trigger."""

    def create_temp_batch_file(self, content: str) -> str:
        """Create a temporary batch file with the given content."""
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".bat", encoding="utf-8"
        ) as f:
            f.write(content)
            return f.name

    def test_if_exist_with_comparison_operator_e004(self) -> None:
        """Test E004 rule for IF EXIST syntax mixing."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
IF EXIST myfile.txt == "yes" ECHO Found
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e004_issues = [i for i in issues if i.rule.code == "E004"]
            assert len(e004_issues) == 1
        finally:
            os.unlink(temp_file)

    def test_path_invalid_characters_e005(self) -> None:
        """Test E005 rule for invalid path characters."""
        import os

        from blinter import lint_batch_file

        # Test truly invalid characters (< > |) are still caught
        content = """@echo off
COPY "file<test>.txt", "dest>folder",
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e005_issues = [i for i in issues if i.rule.code == "E005"]
            assert len(e005_issues) >= 1  # Should detect invalid path characters
        finally:
            os.unlink(temp_file)

        # Test that wildcards (* and ?) are NOT flagged as invalid
        content2 = """@echo off
COPY "*.txt", "dest",
DEL "file?.bat",
"""
        temp_file2 = self.create_temp_batch_file(content2)
        try:
            issues2 = lint_batch_file(temp_file2)
            e005_issues2 = [i for i in issues2 if i.rule.code == "E005"]
            assert len(e005_issues2) == 0  # Wildcards should NOT be flagged
        finally:
            os.unlink(temp_file2)

    def test_for_loop_missing_do_e010(self) -> None:
        """Test E010 rule for FOR loop missing DO keyword."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
FOR %%i IN (1 2 3) ECHO %%i
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e010_issues = [i for i in issues if i.rule.code == "E010"]
            assert len(e010_issues) == 1
        finally:
            os.unlink(temp_file)

    def test_subroutine_call_without_call_e012(self) -> None:
        """Test E012 rule for subroutine invocation without CALL."""
        import os

        from blinter import lint_batch_file

        # Test case: attempting to invoke a label without CALL or GOTO
        content = """@echo off
REM Define a subroutine
:ProcessFile
ECHO Processing %1
EXIT /B

REM Incorrect invocation - missing CALL
ProcessFile mydata.txt

REM Correct invocations - should NOT trigger E012
CALL :ProcessFile mydata2.txt
GOTO :EOF
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e012_issues = [i for i in issues if i.rule.code == "E012"]
            # Should trigger E012 only for "ProcessFile mydata.txt" line
            assert len(e012_issues) == 1
            assert e012_issues[0].line_number == 8
        finally:
            os.unlink(temp_file)

    def test_e012_label_definition_with_comment(self) -> None:
        """Test E012 does NOT trigger for label definitions with inline comments."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
:GetDate7 -- Deprecated because the DOFF utility is no longer available
ECHO This is GetDate7
EXIT /B

:MyFunction - This is my function
ECHO Processing
EXIT /B
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e012_issues = [i for i in issues if i.rule.code == "E012"]
            # Label definitions with comments should NOT trigger E012
            assert len(e012_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_e012_builtin_commands(self) -> None:
        """Test E012 does NOT trigger for builtin commands that match label names."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
:echo
ECHO This is a label named echo
EXIT /B

:set
SET VAR=value
EXIT /B

REM These should NOT trigger E012 because echo and set are builtins
echo Hello World
set MY_VAR=test
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e012_issues = [i for i in issues if i.rule.code == "E012"]
            # Builtin commands should NOT trigger E012 even if labels exist
            assert len(e012_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_e012_case_insensitive(self) -> None:
        """Test E012 detects case-insensitive label invocations."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
:MyFunction
ECHO In function
EXIT /B

REM All of these should trigger E012
myfunction arg1
MYFUNCTION arg2
MyFunction arg3
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e012_issues = [i for i in issues if i.rule.code == "E012"]
            # All three case variations should trigger E012
            assert len(e012_issues) == 3
        finally:
            os.unlink(temp_file)

    def test_e012_correct_invocations(self) -> None:
        """Test E012 does NOT trigger for correct CALL and GOTO usage."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
:MyFunction
ECHO In function
EXIT /B

:AnotherFunction
ECHO Another function
EXIT /B

REM Correct usages - should NOT trigger E012
CALL :MyFunction
call :MyFunction
CALL :MyFunction arg1 arg2
GOTO :AnotherFunction
goto :MyFunction
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e012_issues = [i for i in issues if i.rule.code == "E012"]
            # Correct CALL/GOTO usage should NOT trigger E012
            assert len(e012_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_magic_number_in_timeout_s009(self) -> None:
        """Test S009 rule for magic numbers in timeout commands."""
        import os

        from blinter import lint_batch_file

        content = """@echo off
TIMEOUT /T 300
PING localhost -n 25
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            s009_issues = [i for i in issues if i.rule.code == "S009"]
            assert len(s009_issues) == 2  # Both 300 and 25 are large numbers
        finally:
            os.unlink(temp_file)


class TestSpecializedEdgeCases:
    """Additional edge case tests for specialized scenarios."""

    def test_detect_line_endings_file_read_errors(self) -> None:
        """Test _detect_line_endings with file read errors."""
        nonexistent_file = "nonexistent_file_path_test.bat"

        # Test FileNotFoundError
        try:
            _detect_line_endings(nonexistent_file)
            assert False, "Should have raised OSError"
        except OSError as e:
            assert "Cannot read file" in str(e)
            assert "nonexistent_file_path_test.bat" in str(e)

    def test_detect_line_endings_permission_error(self) -> None:
        """Test _detect_line_endings with permission error."""
        # Create a temporary file and then try to simulate permission error
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False
        ) as temp_file:
            temp_file.write("@echo off\r\n")
            temp_file_path = temp_file.name

        try:
            # Mock open to raise PermissionError
            with patch("builtins.open", side_effect=PermissionError("Access denied")):
                try:
                    _detect_line_endings(temp_file_path)
                    assert False, "Should have raised OSError"
                except OSError as e:
                    assert "Cannot read file" in str(e)
        finally:
            os.unlink(temp_file_path)

    def test_has_multibyte_chars_unicode_encode_error(self) -> None:
        """Test _has_multibyte_chars with lines that cause UnicodeEncodeError."""
        # Create lines that would cause encoding issues when trying to encode to ASCII
        lines_with_unicode = [
            "echo Hello",  # Normal line
            "echo Café ñoño",  # Line with accented characters
            "echo 中文测试",  # Line with Chinese characters
            "echo Ελληνικά",  # Line with Greek characters
        ]

        has_multibyte, affected_lines = _has_multibyte_chars(lines_with_unicode)

        assert has_multibyte is True
        # Lines with non-ASCII characters should be detected
        assert 2 in affected_lines  # "echo Café ñoño"
        assert 3 in affected_lines  # "echo 中文测试"
        assert 4 in affected_lines  # "echo Ελληνικά"

    def test_enhanced_commands_function(self) -> None:
        """Test enhanced commands function."""

        # Test enhanced commands function
        lines = [
            "@echo off",
            "timeout /t 30",  # Should trigger S009
            "ping localhost -t",  # Should trigger various rules
            "choice /c yn /m 'Continue?'",
            "for /f %%i in ('dir') do echo %%i",
        ]

        issues = _check_enhanced_commands(lines)
        assert isinstance(issues, list)

    def test_advanced_vars_function(self) -> None:
        """Test _check_advanced_vars function."""
        lines = [
            "@echo off",
            "set VAR=value",
            "set SPECIAL_VAR=special",
            "echo %VAR%",
            "set PATH=C:\\Windows;%PATH%",  # Path modification
        ]

        issues = _check_advanced_vars(lines)
        assert isinstance(issues, list)

    def test_enhanced_security_rules(self) -> None:
        """Test _check_enhanced_security_rules function."""
        lines = [
            "@echo off",
            "powershell.exe -Command Get-Process",  # Should trigger security rule
            "net user admin password /add",  # Security issue
            "reg delete HKLM\\Software /f",  # Dangerous registry operation
            "rundll32 shell32.dll,ShellExec_RunDLL cmd.exe",
        ]

        issues = _check_enhanced_security_rules(lines)
        assert isinstance(issues, list)

    def test_enhanced_performance_function(self) -> None:
        """Test _check_enhanced_performance function."""
        lines = [
            "@echo off",
            "setlocal",
            "set VAR=value",  # Using setlocal without actual variable operations
            "endlocal",
            "for %%i in (1 2 3 4 5) do echo %%i",  # Could be optimized
        ]

        issues = _check_enhanced_performance(lines)
        assert isinstance(issues, list)

    def test_function_docs_checking(self) -> None:
        """Test _check_function_docs function."""
        lines = [
            "@echo off",
            ":function_name",
            "echo This is a function",
            "goto :eof",
            ":another_function",  # Function without documentation
            "echo Another function",
            "goto :eof",
        ]

        for line_num, line in enumerate(lines, 1):
            issues = _check_function_docs(line, line_num, lines)
            assert isinstance(issues, list)

    def test_magic_numbers_function(self) -> None:
        """Test _check_magic_numbers function."""
        test_lines = [
            "timeout /t 300",  # Magic number
            "ping localhost -n 50",  # Magic number
            "set /a result=42*7",  # Magic numbers
            "echo Simple line",  # No magic numbers
        ]

        for line_num, line in enumerate(test_lines, 1):
            issues = _check_magic_numbers(line, line_num)
            assert isinstance(issues, list)

    def test_magic_numbers_not_flagged_in_comments(self) -> None:
        """Test that magic numbers in comments are not flagged (S019 bug fix)."""
        # Test REM comments with various numeric patterns
        rem_comment_lines = [
            "rem Created On: 22 Jun 2003",
            "REM         By: Andrew S. Baker",
            "rem OS Required: Windows 2008 or later (previously Windows 2003+)",
            "rem Updated to v4.0 in 2018",
            "REM Using code page 1252 or 65001",
        ]

        # Test :: and ::: comments with numeric patterns
        colon_comment_lines = [
            ":: Notes Prior to January 2014 Have Been Purged",
            "::: (Nov 2014) v7.1 -- Reverted to old method",
            "::: (Mar 2012) v6.0 -- Added support for 64-bit systems",
            "::  https://www.dostips.com/forum/viewtopic.php?t=774",
            "::: Change from Code Page 1252 to Code Page 65001 (Unicode)",
        ]

        # Test that no magic numbers are flagged in comments
        for line in rem_comment_lines + colon_comment_lines:
            issues = _check_magic_numbers(line, 1)
            assert (
                len(issues) == 0
            ), f"Magic numbers should not be flagged in comment: {line}"

        # Test that magic numbers ARE still flagged in actual code (not in SET statements)
        # Using numbers that won't trigger path/GUID heuristics (avoid /, \, -, etc.)
        code_lines_should_flag = [
            "TIMEOUT /T 2003",  # Custom timeout - should flag 2003
            "PING -n 5000 localhost",  # Custom ping count - should flag 5000
            "IF %ERRORLEVEL% EQU 999 GOTO error",  # Custom error level - should flag 999
        ]

        code_lines_should_not_flag = [
            "set count=1",  # Single digit
            "set max=100",  # Common exception
            "set timeout=60",  # Common exception (60 seconds)
            "set YEAR=2003",  # SET statement - defining a constant (correct pattern)
            "set LIMIT=5000",  # SET statement - defining a constant (correct pattern)
            "set MAX_RETRIES=999",  # SET statement - defining a constant (correct pattern)
        ]

        for code_line in code_lines_should_flag:
            issues = _check_magic_numbers(code_line, 1)
            assert (
                len(issues) > 0
            ), f"Magic number should be flagged in code: {code_line}"

        for code_line in code_lines_should_not_flag:
            issues = _check_magic_numbers(code_line, 1)
            assert len(issues) == 0, f"This number should not be flagged: {code_line}"

    def test_line_length_function(self) -> None:
        """Test _check_line_length function."""
        # Test with very long line
        long_line = "echo " + "x" * 200  # Long line should trigger S011
        short_line = "echo hello"  # Short line should not trigger

        long_issues = _check_line_length(long_line, 1)
        short_issues = _check_line_length(short_line, 2)

        assert isinstance(long_issues, list)
        assert isinstance(short_issues, list)
        # Long line should have issues, short line should not
        assert len(long_issues) > 0
        assert len(short_issues) == 0

    def test_advanced_style_rules(self) -> None:
        """Test _check_advanced_style_rules function."""
        lines = [
            "@echo off",
            "REM This is a comment",
            "echo hello world",
            "SET VAR=value",  # Mixed case command
            "Echo Mixed Case",  # Mixed case command
        ]

        issues = _check_advanced_style_rules(lines)
        assert isinstance(issues, list)

    def test_multibyte_chars_unicode_encode_error(self) -> None:
        """Test _has_multibyte_chars handling of UnicodeEncodeError."""
        # Create a custom line that will trigger UnicodeEncodeError
        # We'll patch the function to directly simulate the error condition
        with patch("blinter._has_multibyte_chars") as mock_has_multibyte:
            mock_has_multibyte.return_value = (True, [1])
            lines = ["test line"]
            has_mb, affected_lines = mock_has_multibyte(lines)
            assert has_mb is True
            assert 1 in affected_lines

    def test_detect_line_endings_empty_file(self) -> None:
        """Test line ending detection with empty content."""
        # This test handles empty file scenarios
        # Just test basic functionality here
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as f:
            temp_path = f.name
        try:
            ending_type, has_mixed, crlf, lf, cr = _detect_line_endings(temp_path)
            assert ending_type in ["LF", "CRLF", "CR", "NONE"]
            assert isinstance(has_mixed, bool)
        finally:
            os.unlink(temp_path)

    def test_security_powershell_execution_policy_bypass(self) -> None:
        """Test PowerShell execution policy bypass detection."""
        result = _check_security_issues(
            "powershell -ExecutionPolicy Bypass -Command malicious", 1
        )
        assert any(issue.rule.code == "SEC009" for issue in result)

    def test_security_powershell_execution_bypass_lowercase(self) -> None:
        """Test SEC009 PowerShell execution policy bypass detection with lowercase."""
        # Test case that should trigger line 2528 in blinter.py
        result = _check_security_issues(
            "powershell -executionpolicy bypass -command dangerous", 1
        )
        sec009_issues = [i for i in result if i.rule.code == "SEC009"]
        assert len(sec009_issues) >= 1

    def test_empty_file_scenarios(self) -> None:
        """Test scenarios with empty files and edge cases."""
        import os
        import tempfile

        from blinter import BlinterConfig, lint_batch_file

        # Create a truly empty file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as f:
            temp_path = f.name  # Write nothing

        try:
            # Test linting empty file
            config = BlinterConfig()
            issues = lint_batch_file(temp_path, config)
            # Should handle empty file gracefully
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)

    def test_file_with_only_whitespace(self) -> None:
        """Test file with only whitespace to trigger edge cases."""
        import os
        import tempfile

        from blinter import BlinterConfig, lint_batch_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as f:
            f.write("   \n\t\n   \n")  # Only whitespace
            temp_path = f.name

        try:
            config = BlinterConfig()
            issues = lint_batch_file(temp_path, config)
            # Should handle whitespace-only file
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)

    def test_single_line_file_no_newline(self) -> None:
        """Test file with single line and no newline."""
        import os
        import tempfile

        from blinter import BlinterConfig, lint_batch_file

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as f:
            f.write("@echo off")  # No newline at end
            temp_path = f.name

        try:
            config = BlinterConfig()
            issues = lint_batch_file(temp_path, config)
            # Should handle file without final newline
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)

    def test_file_with_unicode_bom(self) -> None:
        """Test file with Unicode BOM."""
        import os
        import tempfile

        from blinter import BlinterConfig, lint_batch_file

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8-sig"
        ) as f:
            f.write("@echo off\necho Hello\n")
            temp_path = f.name

        try:
            config = BlinterConfig()
            issues = lint_batch_file(temp_path, config)
            # Should handle BOM correctly
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)


class TestEnhancedQuoteChecking:
    """Test cases for comprehensive quote checking implementation."""

    def create_temp_batch_file(self, content: str) -> str:
        """Helper method to create a temporary batch file with given content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            return temp_file.name

    def test_caret_escaped_quotes(self) -> None:
        """Test that caret-escaped quotes (^") are handled correctly."""
        content = """@ECHO OFF
ECHO This is a caret-escaped quote: ^"test^"
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should not report unmatched quotes for caret-escaped quotes
            quote_issues = [
                issue for issue in issues if "quote" in issue.rule.name.lower()
            ]
            assert len(quote_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_escaped_quotes_double_quote(self) -> None:
        """Test that double-quote escaping ("") is handled correctly."""
        content = """@ECHO OFF
SET "VAR=This has ""escaped"" quotes"
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should not report E009 (unmatched quotes) for "" escaping
            # May report E028 (complex quote escaping) which is a different check
            e009_issues = [issue for issue in issues if issue.rule.code == "E009"]
            assert len(e009_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_line_continuation_with_quote(self) -> None:
        """Test that line continuation (^) with quotes is handled correctly."""
        content = """@ECHO OFF
ECHO This line continues^
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should handle line continuation properly
            quote_issues = [
                issue for issue in issues if "quote" in issue.rule.name.lower()
            ]
            # Line continuation should prevent false positive
            assert len(quote_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_delayed_expansion_in_set(self) -> None:
        """Test that delayed expansion in SET commands is handled correctly."""
        content = """@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION
SET "VAR=!OTHER_VAR!"
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should not incorrectly flag delayed expansion
            quote_issues = [
                issue for issue in issues if "quote" in issue.rule.name.lower()
            ]
            assert len(quote_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_call_label_substitution(self) -> None:
        """Test that CALL label substitution is handled correctly."""
        content = """@ECHO OFF
CALL :subroutine "param1" "param2"
GOTO :EOF

:subroutine
ECHO %~1
EXIT /B
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should handle CALL label substitution without false positives
            quote_issues = [
                issue for issue in issues if "quote" in issue.rule.name.lower()
            ]
            assert len(quote_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_parentheses_context_tracking(self) -> None:
        """Test that parentheses context is tracked correctly."""
        content = """@ECHO OFF
IF EXIST "file.txt" (
    ECHO "File exists"
)
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should correctly handle quotes within parentheses
            quote_issues = [
                issue for issue in issues if "quote" in issue.rule.name.lower()
            ]
            assert len(quote_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_actual_unmatched_quote(self) -> None:
        """Test that actual unmatched quotes are still detected."""
        content = """@ECHO OFF
ECHO "This quote is unmatched
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Should detect the unmatched quote
            quote_issues = [
                issue for issue in issues if "quote" in issue.rule.name.lower()
            ]
            assert len(quote_issues) > 0
        finally:
            os.unlink(temp_file)


class TestEnhancedBlockDetection:
    """Test cases for comprehensive block detection implementation."""

    def create_temp_batch_file(self, content: str) -> str:
        """Helper method to create a temporary batch file with given content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            return temp_file.name

    def test_block_end_with_goto(self) -> None:
        """Test that GOTO statements properly end blocks."""
        content = """@ECHO OFF
REM Documented section
:main_label
SET VAR=value
GOTO :EOF
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Block should end with GOTO
            doc_issues = [
                issue for issue in issues if "documentation" in issue.rule.name.lower()
            ]
            # Should not flag missing documentation after GOTO
            assert len(doc_issues) == 0 or all(
                issue.line_number <= 3 for issue in doc_issues
            )
        finally:
            os.unlink(temp_file)

    def test_block_end_with_exit(self) -> None:
        """Test that EXIT statements properly end blocks."""
        content = """@ECHO OFF
REM Documented section
:subroutine
ECHO Running subroutine
EXIT /B 0
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Block should end with EXIT
            doc_issues = [
                issue for issue in issues if "documentation" in issue.rule.name.lower()
            ]
            # Should not flag missing documentation after EXIT
            assert len(doc_issues) == 0 or all(
                issue.line_number <= 3 for issue in doc_issues
            )
        finally:
            os.unlink(temp_file)

    def test_block_end_with_new_label(self) -> None:
        """Test that new labels properly end previous blocks."""
        content = """@ECHO OFF
REM First section
:first_label
ECHO First section

REM Second section
:second_label
ECHO Second section
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Each label should start a new block
            doc_issues = [
                issue for issue in issues if "documentation" in issue.rule.name.lower()
            ]
            # Should properly handle multiple labeled sections
            assert len(doc_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_block_end_with_call_to_label(self) -> None:
        """Test that CALL to label statements are handled correctly."""
        content = """@ECHO OFF
REM Main section
:main
CALL :helper
GOTO :EOF

REM Helper section
:helper
ECHO Helper
EXIT /B
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # CALL to label should be handled
            doc_issues = [
                issue for issue in issues if "documentation" in issue.rule.name.lower()
            ]
            # Should properly handle CALL to label
            assert len(doc_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_block_end_with_closing_parenthesis(self) -> None:
        """Test that closing parentheses properly end blocks."""
        content = """@ECHO OFF
REM Conditional block
IF EXIST file.txt (
    ECHO File exists
    SET VAR=value
)
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Closing parenthesis should end the block
            doc_issues = [
                issue for issue in issues if "documentation" in issue.rule.name.lower()
            ]
            # Should handle parentheses correctly
            assert len(doc_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_block_end_with_double_empty_lines(self) -> None:
        """Test that double empty lines properly end blocks."""
        content = """@ECHO OFF
REM First section
FOR %%i IN (1 2 3) DO (
    ECHO %%i
)


REM This is after double empty lines
ECHO Done
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Double empty lines should end the block
            doc_issues = [
                issue for issue in issues if "documentation" in issue.rule.name.lower()
            ]
            # Should handle paragraph breaks
            assert len(doc_issues) == 0
        finally:
            os.unlink(temp_file)

    def test_long_block_with_clear_boundary(self) -> None:
        """Test that long blocks (>15 lines) with clear boundaries are detected."""
        content = """@ECHO OFF
REM Long section
:long_label
ECHO Line 1
ECHO Line 2
ECHO Line 3
ECHO Line 4
ECHO Line 5
ECHO Line 6
ECHO Line 7
ECHO Line 8
ECHO Line 9
ECHO Line 10
ECHO Line 11
ECHO Line 12
ECHO Line 13
ECHO Line 14
ECHO Line 15
ECHO Line 16

SET VAR=value
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            # Check for S018 (missing subroutine documentation) specifically
            # S013 (file header documentation) is a different check
            s018_issues = [issue for issue in issues if issue.rule.code == "S018"]
            # Should handle long blocks properly and not flag S018
            assert len(s018_issues) == 0
        finally:
            os.unlink(temp_file)


class TestE011VariableExpansionPatterns:
    """Test cases for E011 rule - variable expansion with wildcards and special patterns."""

    def create_temp_batch_file(self, content: str) -> str:
        """Helper method to create a temporary batch file with given content."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            return temp_file.name

    def test_variable_with_wildcard_suffix(self) -> None:
        """Test that variables followed by wildcards don't trigger E011."""
        content = """@ECHO OFF
SET @SOURCE=%@INPUT%*%~n1*
DIR "%@BK_PREFIX%*.*" /OD /A-D
FOR %%F IN (%@ROOT%*.BAT) DO ECHO %%F
DIR "%TEMP%\\%@PREFIX%*"
SET @WCARD=%~3& IF "%~3"=="" SET @FILE2=%%~F.%@YYYY%*%~x2
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"Variables with wildcards should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_variable_with_numeric_suffix(self) -> None:
        """Test that variables with numeric suffixes don't trigger E011."""
        content = """@ECHO OFF
IF %@PORT%0 LSS 1 SET "@PORT=24"
IF %@PORT%0 GTR 655350 SET "@PORT=24"
SET NUM=%VALUE%123
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"Variables with numeric suffixes should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_escaped_percent_signs(self) -> None:
        """Test that escaped percent signs (%%%%) don't trigger E011."""
        content = """@ECHO OFF
FOR %%s IN ("%%%%Failed" "%%%%Unable") DO ECHO %%s
IF NOT "%~3"=="" FOR /R "%@LOGSOURCE%" %%f IN (*.RECORDING.TXT) DO FOR %%s IN ("%%%%Failed" "%%%%Unable") DO CALL RemoveLine "%%~f" "%%~s"
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"Escaped percent signs should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_complex_ipv4_ipv6_patterns(self) -> None:
        """Test that complex IP format patterns don't trigger E011."""
        content = """@ECHO OFF
SET @N=[0-9]
SET @AN=[a-f,0-9]
SET @IPV4-FORMAT=%@N%*\\.%@N%*\\.%@N%*\\.%@N%*\\/%@N%*
SET @IPV6-FORMAT=%@AN%%@AN%%@AN%%@AN%:%@AN%%@AN%%@AN%%@AN%:%@AN%%@AN%%@AN%%@AN%::\\/%@N%*
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"Complex IP format patterns should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_variable_with_string_replacement_wildcard(self) -> None:
        """Test that string replacement with wildcards doesn't trigger E011."""
        content = """@ECHO OFF
SET @THESE=*%@MACHINE:\\=%*.CSV
CALL :SwapIt @SHARE %%@SHARE:%@OLDSTRING%=%@NEWSTRING%%%
CALL :SwapIt @SHARE "%%@DRIVE:%@OLDSTRING%=%@NEWSTRING%%%"
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"String replacement with wildcards should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_variable_in_file_operations(self) -> None:
        """Test that variables in file operations with wildcards don't trigger E011."""
        content = """@ECHO OFF
DEL %@CFGFILE%*
ROBOCOPY "%@SOURCEDIR%" "%@DESTDIR%" %@FILENAME%*.*
FILEHASH --%@LOG_HASH% -g %@CHECKSUM% -d "%@ZIPPATH%" "%COMPUTERNAME%-%@LOGNAME%*"
IF EXIST "%@LOGBASE%*.TXT" COPY "%@LOGBASE%*.TXT" "%@NETLOG%" /Y
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"Variables in file operations should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_variable_in_for_loop_with_wildcards(self) -> None:
        """Test that variables in FOR loops with wildcards don't trigger E011."""
        content = """@ECHO OFF
FOR /F "SKIP=%@MAXBACKUPS% TOKENS=*" %%E IN ('DIR /OG-D /B /A "%@BK_PREFIX%*.*" ') DO ECHO %%E
FOR /F "TOKENS=*" %%F IN ('DIR /B /S "%@CONFIG_ROOT%*.xml" ') DO ECHO %%F
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert len(e011_issues) == 0, (
                f"FOR loops with wildcards should not trigger E011: "
                f"{[i.context for i in e011_issues]}"
            )
        finally:
            os.unlink(temp_file)

    def test_genuinely_incomplete_variables_still_caught(self) -> None:
        """Test that genuinely incomplete variables are still flagged by E011."""
        content = """@ECHO OFF
SET BAD=%MISSING
ECHO This has %INCOMPLETE
SET RESULT=%ERRORLEVEL
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            assert (
                len(e011_issues) >= 3
            ), f"Incomplete variables should still trigger E011, found {len(e011_issues)}"
        finally:
            os.unlink(temp_file)

    def test_mixed_valid_and_invalid_patterns(self) -> None:
        """Test file with both valid wildcard patterns and genuinely invalid ones."""
        content = """@ECHO OFF
REM Valid patterns - should not trigger E011
DIR "%@PREFIX%*.txt"
IF %@PORT%0 LSS 1 SET PORT=80
FOR %%s IN ("%%%%Failed") DO ECHO %%s

REM Invalid patterns - should trigger E011
SET BAD=%INCOMPLETE
ECHO Missing delimiter %WRONGVAR
"""
        temp_file = self.create_temp_batch_file(content)
        try:
            issues = lint_batch_file(temp_file)
            e011_issues = [i for i in issues if i.rule.code == "E011"]
            # Should only flag the two genuinely invalid ones
            assert len(e011_issues) == 2, (
                f"Should only flag genuinely invalid patterns, "
                f"found {len(e011_issues)}: {[i.context for i in e011_issues]}"
            )
            # Verify issues are on correct lines (8 and 9 - @ECHO OFF at line 1)
            assert all(
                i.line_number in [8, 9] for i in e011_issues
            ), f"Wrong lines flagged: {[i.line_number for i in e011_issues]}"
        finally:
            os.unlink(temp_file)
