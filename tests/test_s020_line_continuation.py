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
        assert "exceeds 100 characters" in s020_issues[0].context
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
    # Create a line with multiple ^ but doesn't end with one, and is over 100 chars
    content = (
        "@ECHO OFF\n"
        'FOR /F "TOKENS=*" %%i IN (\'TYPE file.txt 2^>NUL ^| FINDSTR /I "test"\') DO ECHO Long line here with extra text %%i\n'
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
    """S020 should NOT trigger for lines exactly at 100 characters."""
    # Create a line that's exactly 100 characters (excluding newline)
    content = "@ECHO OFF\n"
    content += "REM " + "x" * 96 + "\n"  # REM + space + 96 chars = 100 total

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should NOT trigger S020 because line is exactly 100 characters
        assert len(s020_issues) == 0
    finally:
        temp_path.unlink()


def test_s020_89_chars_triggers() -> None:
    """S020 should trigger for lines at 101 characters (just over limit)."""
    # Create a line that's exactly 101 characters
    content = "@ECHO OFF\n"
    content += "REM " + "x" * 97 + "\n"  # REM + space + 97 chars = 101 total

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        issues = blinter.lint_batch_file(str(temp_path))
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]

        # Should trigger S020 because line is 101 characters (over limit)
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


def test_s020_custom_len_120() -> None:
    """S020 should respect custom max_line_length (120 chars)."""
    # Create a 100-character line without continuation
    content = "@ECHO OFF\n" + "REM " + "x" * 96 + "\n"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        # With max_line_length=120, S020 should NOT trigger (100 < 120)
        config = blinter.BlinterConfig(max_line_length=120)
        issues = blinter.lint_batch_file(str(temp_path), config=config)
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
        assert len(s020_issues) == 0
    finally:
        temp_path.unlink()


def test_s020_custom_len_70() -> None:
    """S020 should trigger when line exceeds custom max_line_length (70 chars)."""
    # Create an 80-character line without continuation
    content = "@ECHO OFF\n" + "REM " + "x" * 76 + "\n"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        # With max_line_length=70, S020 SHOULD trigger (80 > 70)
        config = blinter.BlinterConfig(max_line_length=70)
        issues = blinter.lint_batch_file(str(temp_path), config=config)
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
        assert len(s020_issues) == 1
        assert s020_issues[0].line_number == 2
        assert "70 characters" in s020_issues[0].context
    finally:
        temp_path.unlink()


def test_s020_custom_len_with_cont() -> None:
    """S020 should NOT trigger for lines with ^ continuation, regardless of limit."""
    # Create a 100-character line WITH continuation
    content = "@ECHO OFF\n" + "REM " + "x" * 91 + " ^\n" + "    continued\n"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        # Even with max_line_length=70, S020 should NOT trigger (has ^)
        config = blinter.BlinterConfig(max_line_length=70)
        issues = blinter.lint_batch_file(str(temp_path), config=config)
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
        # The first line (100 chars) ends with ^, so should NOT trigger S020
        line_2_s020 = [i for i in s020_issues if i.line_number == 2]
        assert len(line_2_s020) == 0
    finally:
        temp_path.unlink()


def test_s020_and_s011_consistency() -> None:
    """S020 and S011 should both respect the same max_line_length."""
    # Create a 100-character line without continuation
    content = "@ECHO OFF\n" + "REM " + "x" * 96 + "\n"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        # Test with max_line_length=90: both should trigger
        config_90 = blinter.BlinterConfig(max_line_length=90)
        issues_90 = blinter.lint_batch_file(str(temp_path), config=config_90)
        s020_issues_90 = [issue for issue in issues_90 if issue.rule.code == "S020"]
        s011_issues_90 = [issue for issue in issues_90 if issue.rule.code == "S011"]
        assert len(s020_issues_90) == 1  # Should trigger
        assert len(s011_issues_90) == 1  # Should trigger

        # Test with max_line_length=110: neither should trigger
        config_110 = blinter.BlinterConfig(max_line_length=110)
        issues_110 = blinter.lint_batch_file(str(temp_path), config=config_110)
        s020_issues_110 = [issue for issue in issues_110 if issue.rule.code == "S020"]
        s011_issues_110 = [issue for issue in issues_110 if issue.rule.code == "S011"]
        assert len(s020_issues_110) == 0  # Should NOT trigger
        assert len(s011_issues_110) == 0  # Should NOT trigger
    finally:
        temp_path.unlink()


def test_s020_context_custom_len() -> None:
    """S020 context message should reflect custom max_line_length."""
    # Create a 100-character line without continuation
    content = "@ECHO OFF\n" + "REM " + "x" * 96 + "\n"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".bat", delete=False, encoding="utf-8"
    ) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        temp_path = Path(temp_file.name)

    try:
        # With max_line_length=95, check the context message
        config = blinter.BlinterConfig(max_line_length=95)
        issues = blinter.lint_batch_file(str(temp_path), config=config)
        s020_issues = [issue for issue in issues if issue.rule.code == "S020"]
        assert len(s020_issues) == 1
        # Context should mention the custom limit (95), not the default (100)
        assert "95 characters" in s020_issues[0].context
        assert "100 characters" not in s020_issues[0].context
    finally:
        temp_path.unlink()
