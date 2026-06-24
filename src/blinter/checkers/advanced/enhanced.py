"""Enhanced command and deprecation checks."""

import re
from typing import (
    Dict,
    List,
    Optional,
    Tuple,
    cast,
)
from blinter.constants import MAGIC_NUMBER_EXCEPTIONS
from blinter.models import LintIssue
from blinter.patterns import DEPRECATED_COMMANDS, REMOVED_COMMANDS
from blinter.rules.registry import RULES
from blinter.parsing.context import _is_comment_line
from blinter.parsing.structure import _is_in_subroutine_context

def _check_for_f_options(stripped: str, line_number: int) -> Optional[LintIssue]:
    """Check FOR /F without proper options (W020)."""
    if re.match(
        r'\s*for\s+/f\s+(?!.*"[^"]*tokens[^"]*")[^(]*\(', stripped, re.IGNORECASE
    ):
        return LintIssue(
            line_number=line_number,
            rule=RULES["W020"],
            context="FOR /F without explicit tokens/delims options",
        )
    return None

def _check_if_comparison_quotes(stripped: str, line_number: int) -> Optional[LintIssue]:
    """Check IF comparisons without quotes (W021)."""
    if_pattern = r'\s*if\s+(?:not\s+)?%\w+%\s*==\s*[^"\']\w+'
    if re.search(if_pattern, stripped, re.IGNORECASE):
        return LintIssue(
            line_number=line_number,
            rule=RULES["W021"],
            context="IF comparison should be quoted",
        )
    return None

def _check_deprecated_commands(stripped: str, line_number: int) -> List[LintIssue]:
    """Check for deprecated commands (W024) and removed commands (E034)."""
    issues: List[LintIssue] = []

    # Skip comment lines (REM or ::)
    if stripped.lower().startswith("rem ") or stripped.startswith("::"):
        return issues

    # First check for removed commands (more severe - Error level)
    # Special handling for "NET PRINT" (just NET PRINT is removed, not NET itself)
    if re.search(r"\bnet\s+print\b", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E034"],
                context="NET PRINT has been removed - use PowerShell Print cmdlets instead",
            )
        )

    # Check other removed commands
    first_word = stripped.split()[0].lower() if stripped.split() else ""
    if first_word in REMOVED_COMMANDS:
        replacement_map = {
            "caspol": "Code Access Security Policy Tool from SDK",
            "diskcomp": "FC (file comparison)",
            "append": "modify PATH or use full paths",
            "browstat": "NET VIEW or PowerShell",
            "inuse": "HANDLE.EXE from Sysinternals",
            "diskcopy": "ROBOCOPY or XCOPY",
            "streams": "PowerShell Get-Item -Stream",
        }
        replacement = replacement_map.get(first_word, "a modern alternative")
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["E034"],
                context=(
                    f"Command '{first_word.upper()}' has been removed "
                    f"from Windows - use {replacement}"
                ),
            )
        )

    # Check for deprecated commands (Warning level)
    # Special case for NET SEND
    if re.search(r"\bnet\s+send\b", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["W024"],
                context="Use MSG command instead of deprecated 'NET SEND'",
            )
        )

    # Special case for AT command (needs special handling because AT is a common word)
    # Only flag if it looks like the scheduling command (e.g., "at 14:00" or "at \\computer")
    if re.search(r"\bat\s+(\d|\\\\)", stripped, re.IGNORECASE):
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["W024"],
                context="Use SCHTASKS command instead of deprecated 'AT'",
            )
        )

    # Check single-word deprecated commands
    if first_word in DEPRECATED_COMMANDS:
        replacement_map = {
            "wmic": "PowerShell WMI cmdlets (Get-WmiObject/Get-CimInstance)",
            "cacls": "ICACLS command",
            "winrm": "PowerShell Remoting (Enter-PSSession/Invoke-Command)",
            "bitsadmin": "PowerShell BitsTransfer module",
            "nbtstat": "PowerShell Get-NetAdapter cmdlets",
            "dpath": "PATH environment variable modification",
            "keys": "CHOICE or SET /P commands",
            "assign": "drive mounting with modern tools",
            "backup": "modern backup tools",
            "comp": "FC command",
            "edlin": "modern text editors",
            "join": "drive mounting with modern tools",
            "subst": "persistent drive mappings or UNC paths",
        }
        replacement = replacement_map.get(first_word, "a modern alternative")
        issues.append(
            LintIssue(
                line_number=line_number,
                rule=RULES["W024"],
                context=f"Command '{first_word.upper()}' is deprecated - use {replacement}",
            )
        )

    return issues

def _check_cmd_error_handling(
    stripped: str, line_number: int, lines: List[str]
) -> Optional[LintIssue]:
    """Check for missing error handling (W025)."""
    commands_needing_handling = ["del", "copy", "move", "mkdir", "rmdir"]

    for cmd in commands_needing_handling:
        if re.match(rf"\s*{cmd}\s+", stripped, re.IGNORECASE):
            # Check if next 3 lines have error handling
            for j in range(line_number, min(line_number + 3, len(lines) + 1)):
                if j <= len(lines) and (
                    "errorlevel" in lines[j - 1].lower()
                    or "if " in lines[j - 1].lower()
                ):
                    return None

            return LintIssue(
                line_number=line_number,
                rule=RULES["W025"],
                context=f"{cmd.upper()} command without error checking",
            )

    return None

def _check_enhanced_commands(lines: List[str]) -> List[LintIssue]:
    """Check for enhanced command validation issues (W020-W025)."""
    issues: List[LintIssue] = []
    uses_delayed_expansion = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Check for delayed expansion usage
        if re.search(r"!\w+!", stripped):
            uses_delayed_expansion = True

        # Run all line-level checks
        issue = _check_for_f_options(stripped, i)
        if issue:
            issues.append(issue)

        issue = _check_if_comparison_quotes(stripped, i)
        if issue:
            issues.append(issue)

        issues.extend(_check_deprecated_commands(stripped, i))

        issue = _check_cmd_error_handling(stripped, i, lines)
        if issue:
            issues.append(issue)

    # Check for missing SETLOCAL EnableDelayedExpansion (W022)
    if uses_delayed_expansion:
        has_setlocal = any(
            re.search(r"setlocal.*enabledelayedexpansion", line, re.IGNORECASE)
            for line in lines
        )
        if not has_setlocal:
            issues.append(
                LintIssue(
                    line_number=1,
                    rule=RULES["W022"],
                    context="Script uses !var! but missing SETLOCAL EnableDelayedExpansion",
                )
            )

    return issues
