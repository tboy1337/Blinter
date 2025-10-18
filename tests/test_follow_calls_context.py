"""
Tests for follow_calls variable context sharing functionality.

This module tests that when --follow-calls is enabled, variables defined in called
scripts are properly recognized as "defined" in the calling script, eliminating
false positive E006 (undefined variable) errors.
"""

import os
import tempfile

from blinter import BlinterConfig, lint_batch_file


class TestFollowCallsVariableContext:
    """Test variable context sharing with follow_calls enabled."""

    def test_variable_defined_in_called_script_no_error(self) -> None:
        """Variable defined in called script should not trigger E006 error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script that defines HELPER_VAR
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("SET ANOTHER_VAR=another_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script that calls helper and uses HELPER_VAR
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("ECHO Using another variable: %ANOTHER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should NOT have E006 errors for HELPER_VAR or ANOTHER_VAR
            e006_issues = [i for i in issues if i.rule.code == "E006"]
            helper_var_issues = [i for i in e006_issues if "HELPER_VAR" in i.context]
            another_var_issues = [i for i in e006_issues if "ANOTHER_VAR" in i.context]

            assert (
                len(helper_var_issues) == 0
            ), "HELPER_VAR should be recognized as defined"
            assert (
                len(another_var_issues) == 0
            ), "ANOTHER_VAR should be recognized as defined"

    def test_variable_used_before_call_triggers_error(self) -> None:
        """Variable used BEFORE the CALL should still trigger E006 error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script that defines HELPER_VAR
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script that uses HELPER_VAR BEFORE the call
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(
                    "ECHO Using helper variable BEFORE call: %HELPER_VAR%\n"
                )
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write(
                    "ECHO Using helper variable AFTER call: %HELPER_VAR%\n"
                )
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should have E006 error for line 2 (before call) but NOT for line 4 (after call)
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]

            assert len(e006_issues) == 1, "Should have exactly one E006 for HELPER_VAR"
            assert (
                e006_issues[0].line_number == 2
            ), "E006 should be on line 2 (before CALL)"

    def test_multiple_call_statements_accumulate_variables(self) -> None:
        """Multiple CALL statements should accumulate variables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create first helper script
            helper1_script = os.path.join(tmpdir, "helper1.bat")
            with open(helper1_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET VAR1=value1\n")
                file_handle.write("EXIT /b 0\n")

            # Create second helper script
            helper2_script = os.path.join(tmpdir, "helper2.bat")
            with open(helper2_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET VAR2=value2\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script that calls both helpers
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper1_script}"\n')
                file_handle.write("ECHO After first call: %VAR1%\n")
                file_handle.write(f'CALL "{helper2_script}"\n')
                file_handle.write("ECHO After second call: %VAR1% and %VAR2%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should NOT have E006 errors for VAR1 or VAR2
            e006_issues = [i for i in issues if i.rule.code == "E006"]
            var1_issues = [i for i in e006_issues if "VAR1" in i.context]
            var2_issues = [i for i in e006_issues if "VAR2" in i.context]

            assert len(var1_issues) == 0, "VAR1 should be recognized as defined"
            assert len(var2_issues) == 0, "VAR2 should be recognized as defined"

    def test_nonexistent_called_script_graceful_handling(self) -> None:
        """Should handle gracefully when called script doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create main script that calls a nonexistent script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write('CALL "nonexistent.bat"\n')
                file_handle.write("ECHO Using undefined var: %UNDEFINED_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should still work and detect undefined variable
            e006_issues = [
                i
                for i in issues
                if i.rule.code == "E006" and "UNDEFINED_VAR" in i.context
            ]
            assert (
                len(e006_issues) == 1
            ), "Should detect undefined variable even when called script doesn't exist"

    def test_follow_calls_disabled_shows_undefined_error(self) -> None:
        """Without follow_calls, should show E006 for variables from called scripts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint WITHOUT follow_calls
            config = BlinterConfig(follow_calls=False)
            issues = lint_batch_file(main_script, config=config)

            # Should have E006 error for HELPER_VAR
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]
            assert (
                len(e006_issues) == 1
            ), "Should have E006 when follow_calls is disabled"

    def test_circular_call_handling(self) -> None:
        """Should handle circular calls gracefully (script calls itself)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create script that calls itself (circular reference)
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write('IF "%1"=="" EXIT /b 0\n')
                file_handle.write(f'CALL "{main_script}" done\n')
                file_handle.write("EXIT /b 0\n")

            # Should not crash or hang
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Just verify it completes without error
            assert isinstance(issues, list)

    def test_relative_path_call(self) -> None:
        """Should handle relative paths in CALL statements."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script with relative path call
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("CALL helper.bat\n")  # Relative path
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should NOT have E006 error for HELPER_VAR
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]
            assert len(e006_issues) == 0, "Should handle relative path calls"

    def test_percent_dp0_path_call(self) -> None:
        """Should handle %~dp0 syntax in CALL statements."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create subdirectory
            subdir = os.path.join(tmpdir, "scripts")
            os.makedirs(subdir, exist_ok=True)

            # Create called script in subdirectory
            helper_script = os.path.join(subdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script with %~dp0 path
            main_script = os.path.join(subdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write('CALL "%~dp0helper.bat"\n')  # %~dp0 syntax
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should NOT have E006 error for HELPER_VAR
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]
            assert len(e006_issues) == 0, "Should handle %~dp0 syntax in calls"

    def test_unicode_encoding_in_called_script(self) -> None:
        """Should handle Unicode encoding issues gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script with potential encoding issues
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("REM This is a comment with unicode: 你好\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should handle Unicode gracefully and recognize the variable
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]
            assert len(e006_issues) == 0, "Should handle Unicode in called scripts"

    def test_call_in_comment_not_processed(self) -> None:
        """CALL statements in comments should be ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script with CALL in comment
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'REM CALL "{helper_script}"\n')  # CALL in comment
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should have E006 error since CALL in comment shouldn't count
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]
            assert len(e006_issues) == 1, "CALL in comment should be ignored"

    def test_multiple_variables_from_single_call(self) -> None:
        """Single called script defining multiple variables should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script with multiple variables
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET VAR1=value1\n")
                file_handle.write("SET VAR2=value2\n")
                file_handle.write("SET VAR3=value3\n")
                file_handle.write('SET "VAR4=value with spaces"\n')
                file_handle.write("SET /A VAR5=10+20\n")
                file_handle.write("SET /P VAR6=Enter value:\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO %VAR1% %VAR2% %VAR3%\n")
                file_handle.write("ECHO %VAR4% %VAR5% %VAR6%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should NOT have E006 errors for any of these variables
            e006_issues = [i for i in issues if i.rule.code == "E006"]
            var_issues = [
                i
                for i in e006_issues
                if any(
                    var in i.context
                    for var in ["VAR1", "VAR2", "VAR3", "VAR4", "VAR5", "VAR6"]
                )
            ]

            assert (
                len(var_issues) == 0
            ), "All variables from called script should be recognized"

    def test_cmd_extension_call(self) -> None:
        """Should work with .cmd extension as well as .bat."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script with .cmd extension
            helper_script = os.path.join(tmpdir, "helper.cmd")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write("SET HELPER_VAR=helper_value\n")
                file_handle.write("EXIT /b 0\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO Using helper variable: %HELPER_VAR%\n")
                file_handle.write("EXIT /b 0\n")

            # Lint with follow_calls enabled
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)

            # Should NOT have E006 error for HELPER_VAR
            e006_issues = [
                i for i in issues if i.rule.code == "E006" and "HELPER_VAR" in i.context
            ]
            assert len(e006_issues) == 0, "Should handle .cmd extension"


class TestFollowCallsEdgeCases:
    """Test edge cases and error handling for follow_calls."""

    def test_empty_called_script(self) -> None:
        """Should handle empty called scripts gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create empty called script
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("")  # Empty file

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO test\n")
                file_handle.write("EXIT /b 0\n")

            # Should not crash
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)
            assert isinstance(issues, list)

    def test_called_script_with_only_comments(self) -> None:
        """Should handle called scripts with only comments."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script with only comments
            helper_script = os.path.join(tmpdir, "helper.bat")
            with open(helper_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("REM This is a comment\n")
                file_handle.write(":: Another comment\n")
                file_handle.write("REM More comments\n")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO test\n")
                file_handle.write("EXIT /b 0\n")

            # Should not crash
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)
            assert isinstance(issues, list)

    def test_permission_error_on_called_script(self) -> None:
        """Should handle permission errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create called script (we'll simulate permission error by not creating it)
            helper_script = os.path.join(tmpdir, "nonexistent_helper.bat")

            # Create main script
            main_script = os.path.join(tmpdir, "main.bat")
            with open(main_script, "w", encoding="utf-8") as file_handle:
                file_handle.write("@ECHO OFF\n")
                file_handle.write(f'CALL "{helper_script}"\n')
                file_handle.write("ECHO test\n")
                file_handle.write("EXIT /b 0\n")

            # Should not crash even if called script doesn't exist
            config = BlinterConfig(follow_calls=True)
            issues = lint_batch_file(main_script, config=config)
            assert isinstance(issues, list)
