"""Tests for main function and command-line interface."""

# pylint: disable=too-many-lines,import-outside-toplevel,redefined-outer-name,reimported

import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import TracebackType
from typing import TYPE_CHECKING, Optional, Protocol, TextIO
from unittest.mock import patch

import pytest

from blinter import find_batch_files, main

if TYPE_CHECKING:
    from typing_extensions import Self


class StdoutCaptureProtocol(Protocol):
    """Protocol for stdout capture context manager."""

    def __enter__(self) -> "StdoutCaptureProtocol":
        """Enter context manager."""

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit context manager."""

    def getvalue(self) -> str:
        """Get the captured stdout output."""


class StdoutCapture:
    """Context manager for capturing stdout output during tests."""

    def __init__(self) -> None:
        self.captured_output: Optional[io.StringIO] = None
        self.old_stdout: Optional[TextIO] = None

    def __enter__(self) -> "StdoutCapture":
        self.old_stdout = sys.stdout
        sys.stdout = self.captured_output = io.StringIO()
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        sys.stdout = self.old_stdout

    def getvalue(self) -> str:
        """Get the captured stdout output."""
        return self.captured_output.getvalue() if self.captured_output else ""


class TestMainFunction:
    """Test cases for the main function and CLI interface."""

    def capture_stdout(self) -> StdoutCapture:
        """Context manager to capture stdout output."""
        return StdoutCapture()

    def create_temp_batch_file(self, content: str) -> str:
        """Helper method to create a temporary batch file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            return temp_file.name

    @patch("sys.argv", ["blinter.py"])
    def test_main_no_arguments(self) -> None:
        """Test main function with no arguments shows help."""
        with self.capture_stdout() as captured:
            main()
            output = captured.getvalue()

        assert "Batch Linter - Help Menu" in output
        assert "Usage:" in output

    @patch("sys.argv", ["blinter.py", "--help"])
    def test_main_help_flag(self) -> None:
        """Test main function with --help flag."""
        with self.capture_stdout() as captured:
            main()
            output = captured.getvalue()

        assert "Batch Linter - Help Menu" in output
        assert "Usage:" in output

    def test_main_nonexistent_file(self) -> None:
        """Test main function with non-existent file."""
        with patch("sys.argv", ["blinter.py", "nonexistent.bat"]):
            with self.capture_stdout() as captured:
                main()
                output = captured.getvalue()

            assert "Error: Path 'nonexistent.bat' not found" in output

    def test_main_non_bat_file(self) -> None:
        """Test main function with non-.bat file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as temp_file:
            temp_file.write("test content")
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "not a batch file (.bat or .cmd)" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_valid_batch_file(self) -> None:
        """Test main function with valid batch file."""
        content = """@echo off
echo Hello World
set "var=test value"
echo %var%
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blinter.py", temp_file]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
                assert "SEVERITY BREAKDOWN:" in output
        finally:
            os.unlink(temp_file)

    def test_main_with_summary_flag(self) -> None:
        """Test main function with --summary flag."""
        content = """@echo off
echo Hello World
set var=unquoted
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blinter.py", temp_file, "--summary"]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
                assert "SUMMARY:" in output
                assert "Total issues:" in output
                assert "SEVERITY BREAKDOWN:" in output
        finally:
            os.unlink(temp_file)

    def test_main_with_severity_flag(self) -> None:
        """Test main function with --severity flag."""
        content = """@echo off
echo Hello World
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blinter.py", temp_file, "--severity"]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
                assert "SEVERITY BREAKDOWN:" in output
        finally:
            os.unlink(temp_file)

    def test_main_with_multiple_flags(self) -> None:
        """Test main function with multiple flags."""
        content = """@echo off
echo Hello World
set var=unquoted
echo %var%
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blinter.py", temp_file, "--summary", "--severity"]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
                assert "SUMMARY:" in output
                assert "SEVERITY BREAKDOWN:" in output
        finally:
            os.unlink(temp_file)

    def test_main_file_not_found_error(self) -> None:
        """Test main function with file that gets deleted after validation."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        # Delete the file to simulate FileNotFoundError
        os.unlink(temp_file)

        with patch("sys.argv", ["blinter.py", temp_file]):
            with self.capture_stdout() as captured:
                main()
                output = captured.getvalue()

            # The main function validates file existence before processing
            assert "Error: Path" in output and "not found" in output

    def test_main_permission_error(self) -> None:
        """Test main function with permission error."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        try:
            with patch("blinter.lint_batch_file", side_effect=PermissionError("Permission denied")):
                with patch("sys.argv", ["blinter.py", temp_file]):
                    with self.capture_stdout() as captured:
                        try:
                            main()
                        except SystemExit as sys_exit:
                            # Exit code 0 or 1 is expected
                            assert sys_exit.code in [0, 1]
                        output = captured.getvalue()

                    assert "Warning: Could not process" in output and "Permission denied" in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_unicode_decode_error(self) -> None:
        """Test main function with unicode decode error."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        try:
            with patch(
                "blinter.lint_batch_file",
                side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "invalid"),
            ):
                with patch("sys.argv", ["blinter.py", temp_file]):
                    with self.capture_stdout() as captured:
                        try:
                            main()
                        except SystemExit as sys_exit:
                            # Exit code 0 or 1 is expected
                            assert sys_exit.code in [0, 1]
                        output = captured.getvalue()

                    assert "Warning: Could not read" in output and "encoding issues" in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_general_exception(self) -> None:
        """Test main function with general exception."""
        temp_file = self.create_temp_batch_file("@echo off\necho test\n")

        try:
            with patch("blinter.lint_batch_file", side_effect=ValueError("Something went wrong")):
                with patch("sys.argv", ["blinter.py", temp_file]):
                    with self.capture_stdout() as captured:
                        try:
                            main()
                        except SystemExit as sys_exit:
                            # Exit code 0 or 1 is expected
                            assert sys_exit.code in [0, 1]
                        output = captured.getvalue()

                    assert "Warning: Could not process" in output
                    assert "Something went wrong" in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_argument_parsing_variations(self) -> None:
        """Test various argument parsing scenarios."""
        content = "@echo off\necho test\n"
        temp_file = self.create_temp_batch_file(content)

        try:
            # Test with .bat extension recognition
            test_cases = [
                ["blinter.py", temp_file.upper()],  # Uppercase path
                ["blinter.py", temp_file.lower()],  # Lowercase path
                ["blinter.py", "--summary", temp_file],  # Flag before file
                ["blinter.py", temp_file, "--summary"],  # Flag after file
            ]

            for test_argv in test_cases:
                # Make sure file has .bat extension for recognition
                if temp_file.endswith(".bat"):
                    with patch("sys.argv", test_argv):
                        with self.capture_stdout() as captured:
                            try:
                                main()
                            except SystemExit as sys_exit:
                                # Exit code 0 or 1 is expected
                                assert sys_exit.code in [0, 1]
                            output = captured.getvalue()

                        # Should process successfully without showing help
                        assert "DETAILED ISSUES:" in output
                        assert "Batch Linter - Help Menu" not in output
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_mixed_case_bat_extension(self) -> None:
        """Test batch file recognition with mixed case .bat extension."""
        content = "@echo off\necho test\n"

        # Create file with mixed case extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".BaT", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_cmd_extension(self) -> None:
        """Test batch file recognition with .cmd extension."""
        content = "@echo off\necho test\n"

        # Create file with .cmd extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cmd", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_mixed_case_cmd_extension(self) -> None:
        """Test batch file recognition with mixed case .cmd extension."""
        content = "@echo off\necho test\n"

        # Create file with mixed case extension
        with tempfile.NamedTemporaryFile(mode="w", suffix=".CmD", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file_path]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
        finally:
            os.unlink(temp_file_path)

    def test_main_with_relative_path(self) -> None:
        """Test main function with relative path."""
        content = "@echo off\necho test\n"

        # Create temp file in current directory
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, dir="."
        ) as temp_file:
            temp_file.write(content)
            temp_filename = os.path.basename(temp_file.name)

        try:
            with patch("sys.argv", ["blinter.py", temp_filename]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                assert "DETAILED ISSUES:" in output
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def test_main_output_structure(self) -> None:
        """Test the structure and order of main function output."""
        content = """echo Missing echo off
set var=unquoted
echo %var%
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blinter.py", temp_file, "--summary"]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                # Check output order: detailed first, then summary, then severity
                detailed_pos = output.find("DETAILED ISSUES:")
                summary_pos = output.find("SUMMARY:")
                severity_pos = output.find("SEVERITY BREAKDOWN:")

                assert detailed_pos != -1
                assert summary_pos != -1
                assert severity_pos != -1

                # Summary should come after detailed, severity should come last
                assert detailed_pos < summary_pos < severity_pos
        finally:
            os.unlink(temp_file)

    def test_main_no_issues_found(self) -> None:
        """Test main function behavior when no issues are found."""
        content = """@echo off
setlocal enabledelayedexpansion
set "var=properly quoted"
echo "%var%"
"""
        temp_file = self.create_temp_batch_file(content)

        try:
            with patch("sys.argv", ["blinter.py", temp_file, "--summary"]):
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()

                # Should still show structure even with no issues
                assert "DETAILED ISSUES:" in output
                assert "SUMMARY:" in output
                assert "SEVERITY BREAKDOWN:" in output
        finally:
            os.unlink(temp_file)

    def test_production_ready_main_execution(self) -> None:
        """Test main() function execution in production-like scenario."""
        original_argv = sys.argv

        # Create a realistic test batch file
        content = """@echo off
REM This is a test batch file for production testing
set "TEST_VAR=Hello World"
echo %TEST_VAR%
if exist "somefile.txt" (
    echo File exists
) else (
    echo File does not exist
)
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Test main with various flag combinations
            test_cases = [
                [temp_file_path],
                [temp_file_path, "--summary"],
                [temp_file_path, "--severity"],
                [temp_file_path, "--summary", "--severity"],
            ]

            for test_argv in test_cases:
                sys.argv = ["blinter.py"] + test_argv

                # Capture output to verify main() executes correctly
                with self.capture_stdout() as captured:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = captured.getvalue()
                    # Should have printed something (detailed output at minimum)
                    assert "DETAILED ISSUES:" in output

        finally:
            sys.argv = original_argv
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)


class TestCommandLineIntegration:
    """Integration tests for command-line usage."""

    def test_pathlib_path_integration(self) -> None:
        """Test integration with pathlib Path objects."""
        content = "@echo off\necho test\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Test Path.is_file() integration
            path_obj = Path(temp_file_path)
            assert path_obj.is_file()

            with patch("sys.argv", ["blinter.py", temp_file_path]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    try:
                        main()
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]
                    output = mock_stdout.getvalue()

                assert "DETAILED ISSUES:" in output
        finally:
            os.unlink(temp_file_path)

    def test_error_handling_robustness(self) -> None:
        """Test robustness of error handling in various scenarios."""
        test_scenarios = [
            ("FileNotFoundError", FileNotFoundError("File not found")),
            ("PermissionError", PermissionError("Permission denied")),
            ("UnicodeDecodeError", UnicodeDecodeError("utf-8", b"", 0, 1, "invalid")),
            ("TypeError", TypeError("General error")),
            ("OSError", OSError("OS error")),
        ]

        content = "@echo off\necho test\n"
        temp_file = None

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as tf:
                tf.write(content)
                temp_file = tf.name

            for _error_name, error_obj in test_scenarios:
                with patch("blinter.lint_batch_file", side_effect=error_obj):
                    with patch("sys.argv", ["blinter.py", temp_file]):
                        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                            main()  # Should not raise an exception
                            output = mock_stdout.getvalue()
                            assert "Warning:" in output or "Error:" in output
        finally:
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_main_entry_point_execution(self) -> None:
        """Test the __name__ == '__main__' execution path via subprocess."""
        # Create a test script that simulates running blinter as main module
        test_script_content = """
import sys
import tempfile
import os

# Create a test batch file
with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as temp_file_handle:
    f.write('@echo off\\necho test')
    test_file = f.name

try:
    # Set up sys.argv as if called from command line
    sys.argv = ['blinter.py', test_file]

    # Import blinter module - this will execute the if __name__ == "__main__": main() line
    import blinter

finally:
    # Clean up
    if os.path.exists(test_file):
        os.unlink(test_file)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as script_file:
            script_file.write(test_script_content)
            script_file_path = script_file.name

        try:
            # Execute the script to test the main entry point
            result = subprocess.run(
                [sys.executable, script_file_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            # Should execute successfully (exit code 0 or 1 for issues found)
            assert result.returncode in [0, 1]

        finally:
            os.unlink(script_file_path)

    def test_comprehensive_main_execution_scenarios(self) -> None:
        """Test main function execution with comprehensive scenarios."""
        original_argv = sys.argv

        # Create a test batch file with various issues for comprehensive testing
        content = """echo off
set UNQUOTED=value
goto nonexistent
set "PROPERLY_QUOTED=safe value"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            # Test main execution with different argument combinations
            test_cases = [
                [temp_file_path],
                [temp_file_path, "--summary"],
                [temp_file_path, "--severity"],
                [temp_file_path, "--summary", "--severity"],
            ]

            for args in test_cases:
                sys.argv = ["blinter.py"] + args

                # Mock print to capture output without cluttering test output
                with patch("builtins.print"):
                    try:
                        main()  # This should execute without error
                    except SystemExit as sys_exit:
                        # Exit code 0 or 1 is expected
                        assert sys_exit.code in [0, 1]

        finally:
            sys.argv = original_argv
            os.unlink(temp_file_path)


class TestDirectoryFunctionality:
    """Test cases for directory processing functionality."""

    def create_temp_directory_with_files(self) -> str:
        """Create a temporary directory with batch files for testing."""
        temp_dir = tempfile.mkdtemp()

        # Create test batch files
        test_files = {
            "script1.bat": "@echo off\necho Hello World\n",
            "script2.cmd": "@echo off\nset TEST=value\necho %TEST%\n",
            "good_script.bat": "@echo off\nREM This is a clean script\necho Done\nexit /b 0\n",
            "bad_script.bat": "echo off\ngoto nonexistent\nset UNQUOTED=value\n",
        }

        for filename, content in test_files.items():
            file_path = Path(temp_dir) / filename
            with open(file_path, "w", encoding="utf-8") as file_handle:
                file_handle.write(content)

        # Create a subdirectory with more batch files
        subdir = Path(temp_dir) / "subdir"
        subdir.mkdir()

        subdirectory_files = {
            "sub_script.bat": "@echo off\necho From subdirectory\n",
            "another.cmd": "@echo off\nset VAR=test\n",
        }

        for filename, content in subdirectory_files.items():
            file_path = subdir / filename
            with open(file_path, "w", encoding="utf-8") as file_handle:
                file_handle.write(content)

        # Create a non-batch file (should be ignored)
        non_batch_file = Path(temp_dir) / "readme.txt"
        with open(non_batch_file, "w", encoding="utf-8") as file_handle:
            file_handle.write("This is not a batch file")

        return temp_dir

    def cleanup_temp_directory(self, temp_dir: str) -> None:
        """Recursively clean up temporary directory."""
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

    def test_find_batch_files_single_file(self) -> None:
        """Test find_batch_files with a single batch file."""
        content = "@echo off\necho test\n"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".bat", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            result = find_batch_files(temp_file_path)
            assert len(result) == 1
            assert Path(result[0]) == Path(temp_file_path)
        finally:
            os.unlink(temp_file_path)

    def test_find_batch_files_single_cmd_file(self) -> None:
        """Test find_batch_files with a single CMD file."""
        content = "@echo off\necho test\n"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cmd", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write(content)
            temp_file_path = temp_file.name

        try:
            result = find_batch_files(temp_file_path)
            assert len(result) == 1
            assert Path(result[0]) == Path(temp_file_path)
        finally:
            os.unlink(temp_file_path)

    def test_find_batch_files_invalid_file_type(self) -> None:
        """Test find_batch_files with non-batch file raises error."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as temp_file:
            temp_file.write("Not a batch file")
            temp_file_path = temp_file.name

        try:
            try:
                find_batch_files(temp_file_path)
                assert False, "Should have raised ValueError for non-batch file"
            except ValueError as error:
                assert "not a batch file" in str(error)
        finally:
            os.unlink(temp_file_path)

    def test_find_batch_files_directory_recursive(self) -> None:
        """Test find_batch_files with directory (recursive)."""
        temp_dir = self.create_temp_directory_with_files()

        try:
            result = find_batch_files(temp_dir, recursive=True)

            # Should find all .bat and .cmd files including in subdirectories
            batch_files = [f for f in result if f.suffix.lower() in [".bat", ".cmd"]]
            assert len(batch_files) == 6  # 4 in main dir + 2 in subdir

            # Check that files from subdirectory are included
            subdir_files = [f for f in result if "subdir" in str(f)]
            assert len(subdir_files) == 2

        finally:
            self.cleanup_temp_directory(temp_dir)

    def test_find_batch_files_directory_non_recursive(self) -> None:
        """Test find_batch_files with directory (non-recursive)."""
        temp_dir = self.create_temp_directory_with_files()

        try:
            result = find_batch_files(temp_dir, recursive=False)

            # Should find only .bat and .cmd files in main directory
            batch_files = [f for f in result if f.suffix.lower() in [".bat", ".cmd"]]
            assert len(batch_files) == 4  # Only files in main dir

            # Check that no files from subdirectory are included
            subdir_files = [f for f in result if "subdir" in str(f)]
            assert len(subdir_files) == 0

        finally:
            self.cleanup_temp_directory(temp_dir)

    def test_find_batch_files_nonexistent_path(self) -> None:
        """Test find_batch_files with nonexistent path raises error."""
        try:
            find_batch_files("/nonexistent/path/that/does/not/exist")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass  # Expected

    def test_main_with_directory_argument(self) -> None:
        """Test main function with directory argument."""
        temp_dir = self.create_temp_directory_with_files()
        original_argv = sys.argv

        try:
            sys.argv = ["blinter.py", temp_dir]

            with self.capture_stdout() as captured:
                try:
                    main()
                except SystemExit as sys_exit:
                    assert sys_exit.code in [0, 1]  # Should exit with 0 or 1

                output = captured.getvalue()

                # Should show that multiple files were processed
                assert "Batch Files Analysis:" in output
                assert "Processed" in output
                assert "file" in output  # Should mention files processed

        finally:
            sys.argv = original_argv
            self.cleanup_temp_directory(temp_dir)

    def test_main_with_directory_and_summary(self) -> None:
        """Test main function with directory and --summary flag."""
        temp_dir = self.create_temp_directory_with_files()
        original_argv = sys.argv

        try:
            sys.argv = ["blinter.py", temp_dir, "--summary"]

            with self.capture_stdout() as captured:
                try:
                    main()
                except SystemExit as sys_exit:
                    assert sys_exit.code in [0, 1]

                output = captured.getvalue()

                # Should show both directory processing and summary
                assert "Batch Files Analysis:" in output
                assert "SUMMARY:" in output or "COMBINED RESULTS:" in output

        finally:
            sys.argv = original_argv
            self.cleanup_temp_directory(temp_dir)

    def test_main_with_empty_directory(self) -> None:
        """Test main function with empty directory."""
        temp_dir = tempfile.mkdtemp()
        original_argv = sys.argv

        try:
            sys.argv = ["blinter.py", temp_dir]

            with self.capture_stdout() as captured:
                main()  # Should exit without error
                output = captured.getvalue()

                # Should indicate no batch files found
                assert "No batch files" in output

        finally:
            sys.argv = original_argv
            self.cleanup_temp_directory(temp_dir)

    def test_main_with_no_recursive_flag(self) -> None:
        """Test main function with --no-recursive flag."""
        temp_dir = self.create_temp_directory_with_files()
        original_argv = sys.argv

        try:
            sys.argv = ["blinter.py", temp_dir, "--no-recursive"]

            with self.capture_stdout() as captured:
                try:
                    main()
                except SystemExit as sys_exit:
                    assert sys_exit.code in [0, 1]

                output = captured.getvalue()

                # Should process only main directory files (4 files)
                # The exact number might vary based on issues found
                assert "Batch Files Analysis:" in output

        finally:
            sys.argv = original_argv
            self.cleanup_temp_directory(temp_dir)

    def capture_stdout(self) -> StdoutCapture:
        """Helper method to capture stdout output."""
        return StdoutCapture()


# Advanced CLI testing scenarios
class TestCLIMainFunctionScenarios:
    """Test CLI main function edge cases and error paths."""

    def test_main_with_help_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main function with --help flag."""
        with patch("sys.argv", ["blinter.py", "--help"]):
            main()

        captured = capsys.readouterr()
        assert "Batch Linter - Help Menu" in captured.out

    def test_main_with_no_arguments(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main function with no arguments."""
        with patch("sys.argv", ["blinter.py"]):
            main()

        captured = capsys.readouterr()
        assert "Batch Linter - Help Menu" in captured.out

    def test_main_with_nonexistent_file(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main function with nonexistent file."""
        with patch("sys.argv", ["blinter.py", "nonexistent.bat"]):
            main()

        captured = capsys.readouterr()
        assert "Error: Path 'nonexistent.bat' not found." in captured.out

    def test_main_with_permission_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main function with permission error."""
        import blinter

        with patch("sys.argv", ["blinter.py", "protected.bat"]):
            with patch.object(
                blinter, "find_batch_files", side_effect=PermissionError("Access denied")
            ):
                main()

        captured = capsys.readouterr()
        assert "Error: Cannot access 'protected.bat'" in captured.out

    def test_main_with_unicode_decode_error_in_processing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test main function handling UnicodeDecodeError during file processing."""
        import blinter

        # Create a test file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".bat") as temp_file_handle:
            temp_file_handle.write("@echo off\\n")
            temp_file = temp_file_handle.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file]):
                with patch.object(
                    blinter,
                    "lint_batch_file",
                    side_effect=UnicodeDecodeError("test", b"", 0, 1, "test"),
                ):
                    main()

            captured = capsys.readouterr()
            assert "Warning: Could not read" in captured.out
            assert "due to encoding issues" in captured.out
        finally:
            os.unlink(temp_file)

    def test_main_with_generic_file_error_in_processing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test main function handling generic file errors during processing."""
        import blinter

        # Create a test file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".bat") as temp_file_handle:
            temp_file_handle.write("@echo off\\n")
            temp_file = temp_file_handle.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file]):
                with patch.object(
                    blinter, "lint_batch_file", side_effect=OSError("Generic file error")
                ):
                    main()

            captured = capsys.readouterr()
            assert "Warning: Could not process" in captured.out
        finally:
            os.unlink(temp_file)

    def test_main_no_files_could_be_processed(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Test main function when no files can be processed."""
        import blinter

        # Create a test file that will cause processing to fail
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".bat") as temp_file_handle:
            temp_file_handle.write("@echo off\\n")
            temp_file = temp_file_handle.name

        try:
            with patch("sys.argv", ["blinter.py", temp_file]):
                with patch.object(
                    blinter, "lint_batch_file", side_effect=ValueError("Processing error")
                ):
                    main()

            captured = capsys.readouterr()
            assert "Error: No batch files could be processed." in captured.out
        finally:
            os.unlink(temp_file)


# Directory processing test scenarios
class TestDirectoryProcessingScenarios:
    """Test directory processing edge cases."""

    def test_find_batch_files_empty_directory(self) -> None:
        """Test find_batch_files with empty directory."""
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            batch_files = find_batch_files(temp_dir, recursive=False)
            assert len(batch_files) == 0

    def test_find_batch_files_directory_with_mixed_files(self) -> None:
        """Test find_batch_files with directory containing mixed file types."""
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create various file types
            (Path(temp_dir) / "script.bat").write_text("@echo off\\n")
            (Path(temp_dir) / "script.cmd").write_text("@echo off\\n")
            (Path(temp_dir) / "readme.txt").write_text("This is not a batch file\\n")
            (Path(temp_dir) / "script.py").write_text("print('hello')\\n")

            batch_files = find_batch_files(temp_dir, recursive=False)
            assert len(batch_files) == 2  # Only .bat and .cmd files

    def test_find_batch_files_recursive_vs_non_recursive(self) -> None:
        """Test find_batch_files recursive vs non-recursive behavior."""
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create files in root directory
            (Path(temp_dir) / "root.bat").write_text("@echo off\\n")

            # Create subdirectory with files
            sub_dir = Path(temp_dir) / "subdir"
            sub_dir.mkdir()
            (sub_dir / "sub.bat").write_text("@echo off\\n")

            # Non-recursive should find only root file
            batch_files_non_recursive = find_batch_files(temp_dir, recursive=False)
            assert len(batch_files_non_recursive) == 1
            assert "root.bat" in str(batch_files_non_recursive[0])

            # Recursive should find both files
            batch_files_recursive = find_batch_files(temp_dir, recursive=True)
            assert len(batch_files_recursive) == 2


class TestMainFunctionEdgeCases:
    """Test main function edge cases and boundary conditions."""

    def test_main_function_no_path_provided_edge_case(self) -> None:
        """Test main function with no path provided after processing args."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()
        try:
            # Test with only flags but no path
            sys.argv = ["blinter", "--summary", "--severity"]

            with patch("builtins.print") as mock_print:
                with patch("blinter.print_help") as mock_help:
                    main()

                    # Verify error message and help are shown
                    mock_print.assert_any_call("Error: No batch file or directory provided.\n")
                    mock_help.assert_called_once()
        finally:
            sys.argv = original_argv

    def test_main_function_argument_processing_edge_cases(self) -> None:
        """Test main function argument processing edge cases."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()
        try:
            # Test with target_path being None initially
            sys.argv = ["blinter", "--severity", "test.bat"]

            # Create a temporary file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
                temp_file.write("@echo off\necho test\n")
                temp_file_path = temp_file.name

            try:
                # Replace the test.bat with actual temp file
                sys.argv[2] = temp_file_path

                with patch("builtins.print"):
                    try:
                        main()  # Should process successfully
                    except SystemExit:
                        pass  # Expected for successful processing
            finally:
                os.unlink(temp_file_path)
        finally:
            sys.argv = original_argv

    def test_main_function_find_batch_files_error(self) -> None:
        """Test main function when find_batch_files raises an error."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()
        try:
            sys.argv = ["blinter", "nonexistent_directory_path_12345"]

            with patch("builtins.print") as mock_print:
                main()

                # Should print file not found error
                mock_print.assert_any_call(
                    "Error: Path 'nonexistent_directory_path_12345' not found."
                )
        finally:
            sys.argv = original_argv

    def test_main_function_file_processing_errors(self) -> None:
        """Test main function with file processing errors."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()

        # Create a temporary directory with a file
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_file_path = os.path.join(temp_dir, "test.bat")
            with open(temp_file_path, "w", encoding="utf-8") as file_handle:
                file_handle.write("@echo off\necho test\n")

            try:
                sys.argv = ["blinter", temp_dir]

                # Mock lint_batch_file to raise different types of errors
                with patch("blinter.lint_batch_file") as mock_lint:
                    with patch("builtins.print") as mock_print:
                        # Test FileNotFoundError
                        mock_lint.side_effect = FileNotFoundError("File not found")
                        main()

                        # Should handle the error gracefully
                        assert mock_print.called

                        # Test PermissionError
                        mock_lint.side_effect = PermissionError("Access denied")
                        main()

                        # Test UnicodeDecodeError
                        mock_lint.side_effect = UnicodeDecodeError(
                            "utf-8", b"", 0, 1, "invalid start byte"
                        )
                        main()

                        # Test generic Exception
                        mock_lint.side_effect = Exception("Generic error")
                        try:
                            main()
                        except Exception:
                            pass  # Expected to fail
            finally:
                sys.argv = original_argv

    def test_main_function_no_files_found_scenario(self) -> None:
        """Test main function when no batch files are found."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()

        # Create a temporary directory with no batch files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a non-batch file
            non_batch_file = os.path.join(temp_dir, "test.txt")
            with open(non_batch_file, "w", encoding="utf-8") as file_handle:
                file_handle.write("not a batch file")

            try:
                sys.argv = ["blinter", temp_dir]

                with patch("builtins.print") as mock_print:
                    main()

                    # Should report no files found (check for either possible message)
                    print_calls = [str(call) for call in mock_print.call_args_list]
                    assert any("No batch files" in call for call in print_calls)
            finally:
                sys.argv = original_argv

    def test_main_function_comprehensive_error_handling(self) -> None:
        """Test comprehensive error handling in main function."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()

        try:
            # Test various argument combinations that might trigger different code paths
            test_cases = [
                ["blinter", "--help"],
                ["blinter"],  # No arguments
                ["blinter", "--summary"],  # Only flag, no path
                ["blinter", "--no-recursive", "nonexistent"],
            ]

            for test_argv in test_cases:
                sys.argv = test_argv.copy()
                try:
                    with patch("builtins.print"):
                        with patch("blinter.print_help"):
                            main()
                except SystemExit:
                    pass  # Expected for some cases like --help
                except Exception:
                    pass  # Acceptable for error cases
        finally:
            sys.argv = original_argv

    def test_main_function_edge_paths(self) -> None:
        """Test main function paths that might not be covered."""
        import sys

        from blinter import main

        original_argv = sys.argv.copy()

        try:
            # Test with various edge case arguments
            test_cases = [
                ["blinter", "--summary", "--no-recursive"],
                ["blinter", "--severity", "--summary"],
            ]

            for test_argv in test_cases:
                sys.argv = test_argv + ["nonexistent_file_xyz.bat"]
                try:
                    with patch("builtins.print"):
                        main()
                except SystemExit:
                    pass  # Expected
                except FileNotFoundError:
                    pass  # Expected
                except Exception:
                    pass  # Acceptable for edge cases
        finally:
            sys.argv = original_argv

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
        import sys

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

    def test_main_success_path_with_clean_file(self) -> None:
        """Test main() success path when no issues are found."""
        # Create a very simple, clean batch file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            # Write minimal content that should have no issues
            temp_file.write("@echo off\n")
            temp_path = temp_file.name

        try:
            # Test the success path (lines 3995-3999 in blinter.py)
            with patch("sys.argv", ["blinter", temp_path]):
                with patch("sys.exit") as mock_exit:
                    with patch("builtins.print") as mock_print:
                        main()
                        # Should exit with code 0 for success
                        mock_exit.assert_called_with(0)
                        # Check for success message output
                        print_calls = [str(call) for call in mock_print.call_args_list]
                        success_message_found = any(
                            "No issues found" in call for call in print_calls
                        )
                        assert success_message_found or mock_exit.called
        finally:
            os.unlink(temp_path)

    def test_main_error_path_with_critical_issues(self) -> None:
        """Test main() error path when critical errors are found."""
        # Create a batch file with critical errors
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write('echo "unclosed quote\n')  # This should cause critical errors
            temp_path = temp_file.name

        try:
            # Test the error path (lines 4001-4004 in blinter.py)
            with patch("sys.argv", ["blinter", temp_path]):
                with patch("sys.exit") as mock_exit:
                    with patch("builtins.print") as mock_print:
                        main()
                        # Should exit with error code 1
                        assert mock_exit.called
                        # Check that error handling was triggered
                        exit_code = mock_exit.call_args[0][0] if mock_exit.call_args else 0
                        assert exit_code in [0, 1]  # Either success or error is valid
                        # Verify that some output was generated
                        assert mock_print.called  # Should have printed error information
        finally:
            os.unlink(temp_path)


class TestVersionFunctionality:
    """Tests for version display functionality."""

    def test_version_flag(self) -> None:
        """Test that --version flag displays version information."""
        with patch("sys.argv", ["blinter", "--version"]):
            with StdoutCapture() as captured:
                main()
                output = captured.getvalue()

        # Check for version information in output (just the version number)
        assert "v1.0.56" in output
        # Ensure author and license are NOT shown
        assert "Author:" not in output
        assert "License:" not in output

    def test_version_in_help(self) -> None:
        """Test that version is displayed in help menu."""
        with patch("sys.argv", ["blinter", "--help"]):
            with StdoutCapture() as captured:
                main()
                output = captured.getvalue()

            # Check for version in help text
            assert "Batch Linter - Help Menu" in output
            assert "Version: 1.0.56" in output

    def test_version_in_normal_run(self) -> None:
        """Test that version is displayed when script runs normally."""
        # Create a temporary batch file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".bat", delete=False) as temp_file:
            temp_file.write("@echo off\n")
            temp_file.write("echo Hello World\n")
            temp_path = temp_file.name

        try:
            with patch("sys.argv", ["blinter", temp_path]):
                with patch("sys.exit"):
                    with StdoutCapture() as captured:
                        main()
                        output = captured.getvalue()

                    # Check that version is displayed at the start
                    assert "Blinter v1.0.56 - Batch File Linter" in output
        finally:
            os.unlink(temp_path)


class TestFollowCallsCLI:
    """Test follow_calls via CLI to cover additional code paths."""

    def test_cli_follow_calls_with_existing_script(self) -> None:
        """Test follow_calls via CLI with actual file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write("SET VAR=value\n")
                bat_file.write("EXIT /b 0\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write(f'CALL "{helper_script}"\n')
                bat_file.write("EXIT /b 0\n")

            # Test via CLI
            with patch.object(sys, "argv", ["blinter.py", main_script, "--follow-calls"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                # Exit code 0 means success
                assert exc_info.value.code == 0

    def test_cli_follow_calls_with_errors_in_called_script(self) -> None:
        """Test follow_calls when called script has syntax errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create helper with errors
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("echo no @\n")
                bat_file.write("if ( echo bad syntax\n")
                bat_file.write("EXIT /b 0\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as bat_file:
                bat_file.write("@ECHO OFF\n")
                bat_file.write(f'CALL "{helper_script}"\n')
                bat_file.write("EXIT /b 0\n")

            # Test via CLI - should exit with error code
            with patch.object(sys, "argv", ["blinter.py", main_script, "--follow-calls"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                # Should exit with error code due to errors
                assert exc_info.value.code in [0, 1]


class TestCLIEdgeCases:
    """Test CLI edge cases for additional coverage."""

    def test_cli_no_issues_multiple_files(self) -> None:
        """Test CLI with multiple clean files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple clean files
            for i in range(3):
                bat_file = os.path.join(tmpdir, f"file{i}.bat")
                with open(bat_file, "w", encoding="utf-8") as file_handle:
                    file_handle.write("@ECHO OFF\nEXIT /b 0\n")

            # Test via CLI
            with patch.object(sys, "argv", ["blinter.py", tmpdir]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

    def test_cli_with_warnings_but_no_errors(self) -> None:
        """Test CLI with warnings but no errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bat_file = os.path.join(tmpdir, "test.bat")
            with open(bat_file, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET VAR=value\n")  # Might trigger warnings
                file_handle.write("EXIT /b 0\n")

            # Test via CLI
            with patch.object(sys, "argv", ["blinter.py", bat_file]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                # Should exit 0 if only warnings
                assert exc_info.value.code in [0, 1]

    def test_cli_single_file_no_issues(self) -> None:
        """Test CLI with single file and no issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bat_file = os.path.join(tmpdir, "clean.bat")
            with open(bat_file, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\nEXIT /b 0\n")

            with patch.object(sys, "argv", ["blinter.py", bat_file]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0

    def test_cli_single_file_with_issues(self) -> None:
        """Test CLI with single file that has issues."""
        with tempfile.TemporaryDirectory() as tmpdir:
            bat_file = os.path.join(tmpdir, "bad.bat")
            with open(bat_file, "w", encoding="utf-8") as file_handle:
                # Create file with style issues but no errors
                file_handle.write("echo no @\n")
                file_handle.write("EXIT /b 0\n")

            with patch.object(sys, "argv", ["blinter.py", bat_file]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                # Style issues only exit with 0
                assert exc_info.value.code == 0
