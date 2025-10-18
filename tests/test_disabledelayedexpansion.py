"""Tests for DISABLEDELAYEDEXPANSION detection and redundancy checking (P026).

This test module verifies that the linter correctly identifies redundant
SETLOCAL DISABLEDELAYEDEXPANSION usage while recognizing legitimate use cases
such as toggling after ENDLOCAL, protecting literal ! characters, and defensive
programming at script start.
"""

import pathlib

from blinter import lint_batch_file


def test_redundant_disable_mid(tmp_path: pathlib.Path) -> None:
    """Test detection of redundant DISABLEDELAYEDEXPANSION in middle of script."""
    script = tmp_path / "test_redundant.bat"
    script.write_text(
        "@ECHO OFF\n"
        "ECHO Starting script\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "ECHO More lines\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"  # Line 12, should be flagged
        "SET VAR=value\n"
        "ECHO %VAR%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert (
        len(p026_issues) == 1
    ), "Should flag P026 for redundant DISABLEDELAYEDEXPANSION"
    assert p026_issues[0].line_number == 12


def test_not_redundant_after_end(tmp_path: pathlib.Path) -> None:
    """Test that DISABLEDELAYEDEXPANSION after ENDLOCAL is not flagged (toggling pattern)."""
    script = tmp_path / "test_toggling.bat"
    script.write_text(
        "@ECHO OFF\n"
        "SETLOCAL ENABLEDELAYEDEXPANSION\n"
        "SET VAR=test\n"
        "ECHO !VAR!\n"
        "ENDLOCAL\n"
        "\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"
        "SET ANOTHER=value\n"
        "ECHO %ANOTHER%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert (
        len(p026_issues) == 0
    ), "Should NOT flag P026 after ENDLOCAL (toggling pattern)"


def test_not_redundant_at_start(tmp_path: pathlib.Path) -> None:
    """Test that DISABLEDELAYEDEXPANSION at script start is not flagged (defensive)."""
    script = tmp_path / "test_defensive.bat"
    script.write_text(
        "@ECHO OFF\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"
        "SET VAR=value\n"
        "ECHO %VAR%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert (
        len(p026_issues) == 0
    ), "Should NOT flag P026 at script start (defensive programming)"


def test_not_redundant_with_literal(tmp_path: pathlib.Path) -> None:
    """Test that DISABLEDELAYEDEXPANSION is not flagged when protecting literal !."""
    script = tmp_path / "test_literal.bat"
    script.write_text(
        "@ECHO OFF\n"
        "ECHO Line 2\n"
        "ECHO Line 3\n"
        "ECHO Line 4\n"
        "ECHO Line 5\n"
        "ECHO Line 6\n"
        "ECHO Line 7\n"
        "ECHO Line 8\n"
        "ECHO Line 9\n"
        "ECHO Line 10\n"
        "ECHO Line 11\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"
        "ECHO Warning! This is important\n"  # Literal ! character
        "SET MSG=Alert! Check this\n"  # Literal ! character
        "ECHO %MSG%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert (
        len(p026_issues) == 0
    ), "Should NOT flag P026 when script has literal ! characters"


def test_not_redundant_with_enable(tmp_path: pathlib.Path) -> None:
    """Test that DISABLEDELAYEDEXPANSION with ENABLEEXTENSIONS is not flagged."""
    script = tmp_path / "test_enableextensions.bat"
    script.write_text(
        "@ECHO OFF\n"
        "ECHO Line 2\n"
        "ECHO Line 3\n"
        "ECHO Line 4\n"
        "ECHO Line 5\n"
        "ECHO Line 6\n"
        "ECHO Line 7\n"
        "ECHO Line 8\n"
        "ECHO Line 9\n"
        "ECHO Line 10\n"
        "ECHO Line 11\n"
        "SETLOCAL ENABLEEXTENSIONS DISABLEDELAYEDEXPANSION\n"
        "SET VAR=value\n"
        "ECHO %VAR%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert (
        len(p026_issues) == 0
    ), "Should NOT flag P026 with ENABLEEXTENSIONS (common pattern)"


def test_mas_aio_pattern(tmp_path: pathlib.Path) -> None:
    """Test the real-world pattern from MAS_AIO.cmd at script start."""
    script = tmp_path / "test_mas_aio.bat"
    script.write_text(
        "@setlocal DisableDelayedExpansion\n"
        "@echo off\n"
        "\n"
        "setlocal EnableExtensions\n"
        "setlocal DisableDelayedExpansion\n"
        "\n"
        'set "PathExt=.COM;.EXE;.BAT;.CMD;.VBS"\n'
        'set "SysPath=%SystemRoot%\\System32"\n',
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert len(p026_issues) == 0, "Should NOT flag P026 for MAS_AIO.cmd pattern"


def test_multiple_toggles(tmp_path: pathlib.Path) -> None:
    """Test multiple enable/disable toggling patterns."""
    script = tmp_path / "test_multiple_toggles.bat"
    script.write_text(
        "@ECHO OFF\n"
        "SETLOCAL ENABLEDELAYEDEXPANSION\n"
        "SET VAR=first\n"
        "ECHO !VAR!\n"
        "ENDLOCAL\n"
        "\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"
        "SET VAR2=second\n"
        "ECHO %VAR2%\n"
        "ENDLOCAL\n"
        "\n"
        "SETLOCAL ENABLEDELAYEDEXPANSION\n"
        "SET VAR3=third\n"
        "ECHO !VAR3!\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert len(p026_issues) == 0, "Should NOT flag P026 in toggling pattern"


def test_redundant_without_context(tmp_path: pathlib.Path) -> None:
    """Test redundant usage without any legitimate context."""
    script = tmp_path / "test_truly_redundant.bat"
    script.write_text(
        "@ECHO OFF\n"
        "ECHO Starting\n"
        "ECHO Line 3\n"
        "ECHO Line 4\n"
        "ECHO Line 5\n"
        "ECHO Line 6\n"
        "ECHO Line 7\n"
        "ECHO Line 8\n"
        "ECHO Line 9\n"
        "ECHO Line 10\n"
        "ECHO Line 11\n"
        "REM This is redundant\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"
        "SET MYVAR=test\n"
        "ECHO %MYVAR%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert len(p026_issues) == 1, "Should flag P026 for truly redundant usage"


def test_case_insensitive_detection(tmp_path: pathlib.Path) -> None:
    """Test that detection works with various case combinations."""
    script = tmp_path / "test_case.bat"
    script.write_text(
        "@ECHO OFF\n"
        "ECHO Line 2\n"
        "ECHO Line 3\n"
        "ECHO Line 4\n"
        "ECHO Line 5\n"
        "ECHO Line 6\n"
        "ECHO Line 7\n"
        "ECHO Line 8\n"
        "ECHO Line 9\n"
        "ECHO Line 10\n"
        "ECHO Line 11\n"
        "setlocal disabledelayedexpansion\n"
        "SET VAR=value\n"
        "ECHO %VAR%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert (
        len(p026_issues) == 1
    ), "Should detect DISABLEDELAYEDEXPANSION case-insensitively"


def test_line_10_boundary(tmp_path: pathlib.Path) -> None:
    """Test the boundary at line 10 for defensive programming exception."""
    script = tmp_path / "test_line10.bat"
    script.write_text(
        "@ECHO OFF\n"  # Line 1
        "ECHO Line 2\n"  # Line 2
        "ECHO Line 3\n"  # Line 3
        "ECHO Line 4\n"  # Line 4
        "ECHO Line 5\n"  # Line 5
        "ECHO Line 6\n"  # Line 6
        "ECHO Line 7\n"  # Line 7
        "ECHO Line 8\n"  # Line 8
        "ECHO Line 9\n"  # Line 9
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"  # Line 10 - should NOT be flagged
        "SET VAR=value\n"
        "ECHO %VAR%\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert len(p026_issues) == 0, "Should NOT flag P026 at line 10 (boundary)"


def test_line_11_flagged(tmp_path: pathlib.Path) -> None:
    """Test that line 11 is flagged when redundant."""
    script = tmp_path / "test_line11.bat"
    script.write_text(
        "@ECHO OFF\n"  # Line 1
        "ECHO Line 2\n"  # Line 2
        "ECHO Line 3\n"  # Line 3
        "ECHO Line 4\n"  # Line 4
        "ECHO Line 5\n"  # Line 5
        "ECHO Line 6\n"  # Line 6
        "ECHO Line 7\n"  # Line 7
        "ECHO Line 8\n"  # Line 8
        "ECHO Line 9\n"  # Line 9
        "ECHO Line 10\n"  # Line 10
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"  # Line 11 - should be flagged
        "SET VAR=value\n"
        "ECHO %VAR%\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert len(p026_issues) == 1, "Should flag P026 at line 11 (after boundary)"
    assert p026_issues[0].line_number == 11


def test_complex_mixed_patterns(tmp_path: pathlib.Path) -> None:
    """Test a complex script with both redundant and legitimate usage."""
    script = tmp_path / "test_complex.bat"
    script.write_text(
        "@ECHO OFF\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"  # Line 2 - OK (defensive)
        "ECHO Starting\n"
        "\n"
        "SETLOCAL ENABLEDELAYEDEXPANSION\n"
        "SET VAR=test\n"
        "ECHO !VAR!\n"
        "ENDLOCAL\n"
        "\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"  # Line 10 - OK (after ENDLOCAL)
        "SET VAR2=value\n"
        "ECHO %VAR2%\n"
        "ENDLOCAL\n"
        "\n"
        "REM Some more code\n"
        "ECHO More processing\n"
        "ECHO More processing\n"
        "ECHO More processing\n"
        "\n"
        "SETLOCAL DISABLEDELAYEDEXPANSION\n"  # Line 20 - REDUNDANT
        "SET VAR3=another\n"
        "ECHO %VAR3%\n"
        "ENDLOCAL\n",
        encoding="utf-8",
    )

    issues = lint_batch_file(str(script))
    p026_issues = [issue for issue in issues if issue.rule.code == "P026"]
    assert len(p026_issues) == 1, "Should flag only truly redundant usage"
    assert p026_issues[0].line_number == 20
