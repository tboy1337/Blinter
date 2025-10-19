"""
Test cases for S020 rule: Long line without continuation.

This test file specifically validates that S020 correctly identifies:
1. Long lines with ^ for escaping (should trigger S020)
2. Long lines ending with ^ for continuation (should NOT trigger S020)
3. Long lines with no ^ (should trigger S020)
4. Short lines with ^ escaping (should NOT trigger S020)
"""

from pathlib import Path
import tempfile

import blinter


def test_s020_long_caret_escape() -> None:
    """S020 should trigger for long lines with ^ used for escaping, not continuation."""
    content = (
        "@ECHO OFF\n"
        'IF /I "%~1"=="STARTED" FOR /F "TOKENS=*" %%d IN (\'DATEINFO -S %@DATEFMT% -Q 2^>NUL\') DO SET @SCRIPT_BEG#="%%~d"\n'
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should trigger S020 because line is long and doesn't END with ^
        assert len(s020_issues) == 1
        assert s020_issues[0].line_number == 2
        assert "exceeds 88 characters" in s020_issues[0].context
    finally:
        temp_path.unlink()


def test_s020_proper_continuation() -> None:
    """S020 should NOT trigger for long lines that properly use ^ for continuation."""
    content = (
        "@ECHO OFF\n"
        'COPY "C:\\Very\\Long\\Path\\With\\Many\\Directories\\file.txt" "C:\\Another\\Very\\Long\\Path\\file.txt" ^\n'
        "     /Y /V\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should NOT trigger S020 because line ends with ^
        assert len(s020_issues) == 0
    finally:
        temp_path.unlink()


def test_s020_long_line_no_caret() -> None:
    """S020 should trigger for long lines without any ^ character."""
    content = (
        "@ECHO OFF\n"
        "IF DEFINED $CODEPAGE FOR /F \"TOKENS=1* DELIMS=:\" %%B IN ('CHCP %$CODEPAGE%') DO SET @CHCP_STATUS= {Restoring Code Page:%%C}\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should trigger S020 because line is long and has no continuation
        assert len(s020_issues) == 1
        assert s020_issues[0].line_number == 2
    finally:
        temp_path.unlink()


def test_s020_short_line_caret_esc() -> None:
    """S020 should NOT trigger for short lines with ^ escaping."""
    content = "@ECHO OFF\nECHO Test 2^>NUL\n"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should NOT trigger S020 because line is short
        assert len(s020_issues) == 0
    finally:
        temp_path.unlink()


def test_s020_trailing_ws_caret() -> None:
    """S020 should handle lines with trailing whitespace after ^."""
    content = (
        "@ECHO OFF\n"
        'COPY "C:\\Very\\Long\\Path\\With\\Many\\Directories\\file.txt" "C:\\Another\\Very\\Long\\Path\\file.txt" ^   \n'
        "     /Y /V\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should NOT trigger S020 because line ends with ^ (after rstrip)
        assert len(s020_issues) == 0
    finally:
        temp_path.unlink()


def test_s020_multiple_carets() -> None:
    """S020 should trigger if line has multiple ^ but doesn't end with one."""
    content = (
        "@ECHO OFF\n"
        'FOR /F "TOKENS=*" %%i IN (\'TYPE file.txt 2^>NUL ^| FINDSTR /I "test"\') DO ECHO Long line here %%i\n'
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should trigger S020 because line is long and doesn't END with ^
        assert len(s020_issues) == 1
        assert s020_issues[0].line_number == 2
    finally:
        temp_path.unlink()


def test_s020_exactly_88_chars() -> None:
    """S020 should NOT trigger for lines exactly at 88 characters."""
    # Create a line that's exactly 88 characters (excluding newline)
    content = "@ECHO OFF\n"
    content += "REM " + "x" * 84 + "\n"  # REM + space + 84 chars = 88 total

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should NOT trigger S020 because line is exactly 88 characters
        assert len(s020_issues) == 0
    finally:
        temp_path.unlink()


def test_s020_89_chars_triggers() -> None:
    """S020 should trigger for lines at 89 characters (just over limit)."""
    # Create a line that's exactly 89 characters
    content = "@ECHO OFF\n"
    content += "REM " + "x" * 85 + "\n"  # REM + space + 85 chars = 89 total

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should trigger S020 because line is 89 characters (over limit)
        assert len(s020_issues) == 1
        assert s020_issues[0].line_number == 2
    finally:
        temp_path.unlink()


def test_s020_github_line_109() -> None:
    """Test the exact example from GitHub issue - line 109 should trigger S020."""
    content = (
        "@ECHO OFF\n"
        'IF /I "%~1"=="STARTED" FOR /F "TOKENS=*" %%d IN (\'DATEINFO -S %@DATEFMT% -Q 2^>NUL\') DO SET @SCRIPT_BEG#="%%~d"\n'
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
        s011_issues = [issue for issue in issues if issue.rule.code == "S011"]

        # Both S011 and S020 should trigger
        assert len(s011_issues) >= 1  # S011 triggers for line too long
        assert len(s020_issues) == 1  # S020 should now trigger (this was the bug)
        assert s020_issues[0].line_number == 2
    finally:
        temp_path.unlink()


def test_s020_github_line_111() -> None:
    """Test the exact example from GitHub issue - line 111 should trigger both S011 and S020."""
    content = (
        "@ECHO OFF\n"
        "IF DEFINED $CODEPAGE FOR /F \"TOKENS=1* DELIMS=:\" %%B IN ('CHCP %$CODEPAGE%') DO SET @CHCP_STATUS= {Restoring Code Page:%%C}\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
        s011_issues = [issue for issue in issues if issue.rule.code == "S011"]

        # Both S011 and S020 should trigger
        assert len(s011_issues) >= 1  # S011 triggers for line too long
        assert len(s020_issues) == 1  # S020 should trigger
        assert s020_issues[0].line_number == 2
    finally:
        temp_path.unlink()
