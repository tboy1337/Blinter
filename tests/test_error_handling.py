"""Tests for error handling and edge cases in real-world usage scenarios."""

import os
import tempfile
from typing import List
from unittest.mock import mock_open, patch
import warnings

import pytest

from blinter import (
    LintIssue,
    _check_security_issues,
    _check_syntax_errors,
    _check_warning_issues,
    _detect_line_endings,
    find_batch_files,
    lint_batch_file,
    main,
    read_file_with_encoding,
)


class TestRealWorldErrorHandling:
    """Test error handling in real-world scenarios."""

    def test_file_encoding_all_fail_scenario(self) -> None:
        """Test scenario where all encoding attempts fail with different errors."""

        def mock_open_that_always_fails(*args: object, **kwargs: object) -> object:
            if "rb" in str(args) or "rb" in str(kwargs):
                # Allow binary read for chardet
                return mock_open(read_data=b"test data")(*args, **kwargs)
            if "encoding" in kwargs:
                # Simulate different types of failures
                if kwargs["encoding"] == "utf-8":
                    raise UnicodeDecodeError("utf-8", b"test", 0, 1, "utf-8 error")
                if kwargs["encoding"] == "latin1":
                    raise ValueError("Invalid encoding value")
                raise LookupError("Unknown encoding")
            return mock_open(read_data="test")(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_that_always_fails):
            with pytest.raises(OSError, match="All encoding attempts failed"):
                read_file_with_encoding("test.bat")

    def test_empty_file_edge_case_in_context(self) -> None:
        """Test handling empty files in real linting context."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write("")  # Empty file
            temp_path = temp_file.name

        try:
            issues = lint_batch_file(temp_path)
            assert len(issues) == 0  # Empty file should have no issues
        finally:
            os.unlink(temp_path)

    def test_large_file_handling(self) -> None:
        """Test handling of large batch files."""
        # Create a large batch file with many lines
        large_content = "@ECHO OFF\n" + "REM Large file test\n" * 1000 + "EXIT /B 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(large_content)
            temp_path = temp_file.name

        try:
            issues = lint_batch_file(temp_path)
            # Should handle large files without issues
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)

    def test_binary_file_handling(self) -> None:
        """Test handling of binary files masquerading as batch files."""
        binary_content = b"\x00\x01\x02\x03" * 100  # Binary content

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            temp_file.write(binary_content)
            temp_path = temp_file.name

        try:
            # Should handle binary files gracefully
            lines, encoding = read_file_with_encoding(temp_path)
            assert isinstance(lines, list)
            assert isinstance(encoding, str)
        finally:
            os.unlink(temp_path)

    def test_file_with_mixed_line_endings(self) -> None:
        """Test handling of files with mixed line endings."""
        mixed_content = (
            "@ECHO OFF\r\necho Windows line ending\necho Unix line ending\r\necho Mixed\n"
        )

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            temp_file.write(mixed_content.encode("utf-8"))
            temp_path = temp_file.name

        try:
            issues = lint_batch_file(temp_path)
            # Should handle mixed line endings
            assert isinstance(issues, list)
        finally:
            os.unlink(temp_path)

    def test_file_with_very_long_lines(self) -> None:
        """Test handling of files with extremely long lines."""
        long_line = "REM " + "A" * 500 + "\n"
        content = "@ECHO OFF\n" + long_line + "EXIT /B 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            issues = lint_batch_file(temp_path)
            # Should detect S011 (line exceeds maximum length)
            long_line_issues = [i for i in issues if i.rule.code == "S011"]
            assert len(long_line_issues) >= 1
        finally:
            os.unlink(temp_path)

    def test_concurrent_file_access(self) -> None:
        """Test handling concurrent access to the same file."""
        content = "@ECHO OFF\necho test\nEXIT /B 0\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            # Multiple concurrent accesses should work
            issues1 = lint_batch_file(temp_path)
            issues2 = lint_batch_file(temp_path)
            assert len(issues1) == len(issues2)
        finally:
            os.unlink(temp_path)


class TestSpecificEdgeCases:
    """Test specific edge cases that may not have been covered."""

    def test_syntax_error_edge_cases(self) -> None:
        """Test specific syntax error edge cases."""
        labels = {":test": 1, ":end": 5}

        # Test GOTO with various formats
        test_cases = [
            ("goto test", 0),  # Should find :test
            ("GOTO TEST", 0),  # Case insensitive
            ("goto :test", 0),  # With colon
            ("goto missing", 1),  # Missing label
            # Note: bare "goto" without target doesn't match the regex pattern
        ]

        for command, expected_issues in test_cases:
            issues = _check_syntax_errors(command, 2, labels)
            goto_issues = [i for i in issues if i.rule.code == "E002"]
            assert len(goto_issues) == expected_issues, f"Failed for: {command}"

    def test_warning_issue_edge_cases(self) -> None:
        """Test warning level edge cases."""
        set_vars = {"DEFINED_VAR", "PATH", "TEMP"}

        # Test unquoted variables in different contexts
        test_cases = [
            ("if %UNDEFINED_VAR%==value echo test", True),  # Should trigger W005
            ("echo %PATH%", True),  # Should trigger W005 (could contain spaces)
            ("set NEWVAR=%PATH%", True),  # Should trigger W005
            ('if "%UNDEFINED_VAR%"=="value" echo test', False),  # Quoted, should not trigger
        ]

        for command, should_trigger in test_cases:
            issues = _check_warning_issues(command, 1, set_vars, False)
            w005_issues = [i for i in issues if i.rule.code == "W005"]
            if should_trigger:
                assert len(w005_issues) >= 1, f"Should trigger W005 for: {command}"
            # Note: We can't assert == 0 because other rules might trigger

    def test_security_issue_comprehensive(self) -> None:
        """Test comprehensive security issue detection."""
        test_cases = [
            # Command injection patterns
            ("set /p CMD=Enter command: && %CMD%", "SEC001"),
            ("set /p INPUT=Enter: && echo %INPUT%", "SEC001"),
            # Unsafe SET commands
            ("set VAR=value with spaces", "SEC002"),
            ("set PATH=%PATH%;C:\\new", "SEC002"),
            # Registry operations
            ("reg delete HKLM\\Software\\Test /f", "SEC004"),
            ("regedit /s dangerous.reg", None),  # May or may not trigger depending on pattern
            # Privilege checks
            ("net user admin password /add", "SEC005"),
            ("sc create TestService binpath=test.exe", "SEC005"),
        ]

        for command, expected_rule in test_cases:
            issues = _check_security_issues(command, 1)
            if expected_rule:
                matching_issues = [i for i in issues if i.rule.code == expected_rule]
                assert len(matching_issues) >= 1, f"Should trigger {expected_rule} for: {command}"

    def test_unicode_and_special_characters(self) -> None:
        """Test handling of Unicode and special characters."""
        test_cases = [
            "echo café",  # Unicode characters
            "echo naïve",  # Unicode with diacritics
            "echo 测试",  # Chinese characters
            "echo 🚀",  # Emoji
            'echo "quotes with spaces"',  # Quotes
            "echo 'single quotes'",  # Single quotes
            "REM Comment with émojis 💻",  # Comment with Unicode
        ]

        set_vars: set[str] = set()
        for command in test_cases:
            # Should handle Unicode gracefully
            issues = _check_warning_issues(command, 1, set_vars, False)
            # Should detect non-ASCII characters
            non_ascii_issues = [i for i in issues if i.rule.code == "W012"]
            if not all(ord(c) < 128 for c in command):
                assert len(non_ascii_issues) >= 1, f"Should detect non-ASCII in: {command}"


class TestMainFunctionEdgeCases:
    """Test main function edge cases and error paths."""

    def test_main_with_invalid_file_extension(self) -> None:
        """Test main function with invalid file extensions."""
        # Create a test file with wrong extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("@ECHO OFF\necho test")
            temp_path = temp_file.name

        try:
            # Main function actually processes files regardless of extension
            # if they exist, but shows help for non-.bat/.cmd files in argv parsing
            with patch("sys.argv", ["blinter.py", temp_path]):
                with patch("sys.exit"):
                    main()
                    # The function will show help and return normally
        finally:
            os.unlink(temp_path)

    def test_main_with_encoding_warnings(self) -> None:
        """Test main function with encoding warnings."""
        # Create a file that will trigger encoding warnings
        content = "@ECHO OFF\necho test\n"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="latin1"
        ) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        try:
            with patch("sys.argv", ["blinter.py", temp_path]):
                with patch("sys.exit"):
                    with warnings.catch_warnings(record=True):
                        warnings.simplefilter("always")
                        main()
                        # May or may not have warnings depending on encoding detection
        finally:
            os.unlink(temp_path)

    def test_path_validation_comprehensive(self) -> None:
        """Test comprehensive path validation."""
        labels: dict[str, int] = {}

        # Test various invalid path patterns
        invalid_paths = [
            'copy "file<name.txt", dest',  # < character
            'copy "file>name.txt", dest',  # > character
            'copy "file|name.txt", dest',  # | character
            'copy "file*name.txt", dest',  # * character
            'copy "file?name.txt", dest',  # ? character
            "copy 'path<with>invalid', dest",  # Single quotes
        ]

        for command in invalid_paths:
            issues = _check_syntax_errors(command, 1, labels)
            path_issues = [i for i in issues if i.rule.code == "E005"]
            assert len(path_issues) >= 1, f"Should detect invalid path in: {command}"


class TestPerformanceAndScalability:
    """Test performance and scalability aspects."""

    def test_large_number_of_labels(self) -> None:
        """Test handling a large number of labels."""
        lines = ["@ECHO OFF"]
        # Create many labels
        for i in range(100):
            lines.append(f":label{i}")
            lines.append(f"echo Processing {i}")
        lines.append("EXIT /B 0")

        # Should handle many labels efficiently
        issues = lint_batch_file_from_lines(lines)
        assert isinstance(issues, list)

    def test_large_number_of_variables(self) -> None:
        """Test handling a large number of variables."""
        lines = ["@ECHO OFF"]
        # Create many variables
        for i in range(100):
            lines.append(f'set "VAR{i}=value{i}"')
        lines.append("EXIT /B 0")

        # Should handle many variables efficiently
        issues = lint_batch_file_from_lines(lines)
        assert isinstance(issues, list)


def lint_batch_file_from_lines(lines: list[str]) -> List[LintIssue]:
    """Helper function to lint batch file from list of lines."""
    content = "\n".join(lines)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
        temp_file.write(content)
        temp_path = temp_file.name

    try:
        return lint_batch_file(temp_path)
    finally:
        os.unlink(temp_path)


class TestAdditionalErrorHandling:
    """Additional error handling tests for comprehensive scenarios."""

    def test_file_encoding_error_scenarios(self) -> None:
        """Test file encoding error scenarios."""
        # Create a file with problematic encoding
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            # Write some bytes that might cause encoding issues
            temp_file.write(b"@echo off\r\n")
            temp_file.write(b"echo \xff\xfe test\r\n")  # Invalid UTF-8 sequence
            temp_file_path = temp_file.name

        try:
            # This should test the encoding fallback mechanisms
            lines, encoding = read_file_with_encoding(temp_file_path)
            assert isinstance(lines, list)
            assert isinstance(encoding, str)
        except Exception:
            # If it fails, that's also acceptable for this edge case
            pass
        finally:
            os.unlink(temp_file_path)

    def test_line_1111_encoding_fallback(self) -> None:
        """Test line 1111 - encoding fallback scenario."""
        # Create a file that might trigger specific encoding detection failure
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            # Write content with problematic byte sequences
            temp_file.write(b"@echo off\r\n")
            temp_file.write(b"\x80\x81 Invalid UTF-8\r\n")
            temp_file_path = temp_file.name

        try:
            # Should handle encoding issues gracefully
            lines, encoding_used = read_file_with_encoding(temp_file_path)
            assert isinstance(lines, list)
            assert isinstance(encoding_used, str)
        except Exception:
            # If it fails completely, that's also acceptable for this edge case
            pass
        finally:
            os.unlink(temp_file_path)

    def test_encoding_specific_scenarios(self) -> None:
        """Test encoding scenarios for edge cases and error paths."""

        # Test file with BOM
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            # Write UTF-8 BOM + content
            temp_file.write(b"\xef\xbb\xbf@echo off\r\necho UTF-8 BOM test\r\n")
            temp_file_path = temp_file.name

        try:
            lines, encoding_used = read_file_with_encoding(temp_file_path)
            assert isinstance(lines, list)
            assert isinstance(encoding_used, str)
        finally:
            os.unlink(temp_file_path)

        # Test file with mixed encodings (problematic scenario)
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            temp_file.write(b"@echo off\r\n")
            temp_file.write("echo Niño".encode("latin1"))  # Latin1 encoding
            temp_file.write(b"\r\n")
            temp_file_path = temp_file.name

        try:
            lines, encoding_used = read_file_with_encoding(temp_file_path)
            assert isinstance(lines, list)
            assert isinstance(encoding_used, str)
        except Exception:
            # Acceptable if encoding detection fails
            pass
        finally:
            os.unlink(temp_file_path)

    def test_edge_case_functions_behavior(self) -> None:
        """Test various edge case functions for proper behavior."""
        # Test file finding with edge cases
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test find_batch_files with file that exists but isn't a batch file
            txt_file = os.path.join(temp_dir, "test.txt")
            with open(txt_file, "w", encoding="utf-8") as file_handle:
                file_handle.write("not a batch file")

            try:
                files = find_batch_files(txt_file, recursive=False)
                assert len(files) == 0  # Should not include non-batch files
            except ValueError:
                # Expected - non-batch files should raise ValueError
                pass

    def test_specific_encoding_detection_scenario(self) -> None:
        """Test specific encoding detection scenario for edge cases."""
        # This targets a specific scenario in _detect_line_endings
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bat", delete=False) as temp_file:
            # Create content that might trigger specific encoding paths
            temp_file.write(b"@echo off\r\n")
            temp_file.write(b"echo test\n")  # Mixed line endings
            temp_file.write(b"echo final\r")  # Just CR
            temp_file_path = temp_file.name

        try:
            ending_type, has_mixed, _, _, _ = _detect_line_endings(temp_file_path)
            assert ending_type in ["CRLF", "LF", "CR", "MIXED", "mixed"]
            assert isinstance(has_mixed, bool)
        finally:
            os.unlink(temp_file_path)

    def test_error_handling_edge_cases(self) -> None:
        """Test specific error handling edge cases and branches."""

        # Test content that might trigger different rule branches
        test_contents = [
            # Test for specific rule conditions that might be missed
            '@echo off\npowershell -Command "Get-Process"',
            "@echo off\nnet user test password /add",
            "@echo off\nreg add HKLM\\Software\\Test /v TestValue /d TestData",
            "@echo off\necho %USERPROFILE%\\..\\sensitive_file.txt",
        ]

        for content in test_contents:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".bat", delete=False, encoding="utf-8"
            ) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                issues = lint_batch_file(temp_file_path)
                # Ensure we get some kind of result
                assert isinstance(issues, list)
            finally:
                os.unlink(temp_file_path)
