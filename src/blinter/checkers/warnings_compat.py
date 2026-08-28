"""Compatibility and Unicode warning checks extracted from warnings.py."""

import re
from typing import (
    List,
    Optional,
)

from blinter.models import LintIssue
from blinter.patterns import (
    ARCHITECTURE_SPECIFIC_PATTERNS,
    OLDER_WINDOWS_COMMANDS,
    UNICODE_PROBLEMATIC_COMMANDS,
)
from blinter.rules.registry import RULES


def _check_unicode_handling_issue(stripped: str, line_num: int) -> Optional[LintIssue]:
    """Check for Unicode handling issues in commands (W011)."""
    for cmd in UNICODE_PROBLEMATIC_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            has_unicode_risk = False

            # For echo command, only flag if it contains potentially problematic content
            if cmd == "echo":
                has_unicode_risk = _check_echo_unicode_risk(stripped)
            elif cmd in ["findstr", "find"]:
                has_unicode_risk = _check_search_unicode_risk(stripped)
            else:
                has_unicode_risk = _check_general_unicode_risk(stripped)

            if has_unicode_risk:
                return LintIssue(
                    line_number=line_num,
                    rule=RULES["W011"],
                    context=f"Command '{cmd}' may have Unicode handling issues",
                )
            break
    return None


def _extract_echo_content(stripped: str) -> str:
    """Return text after the ECHO command."""
    match = re.match(r"echo\s+(.*)", stripped, re.IGNORECASE)
    return match.group(1) if match else ""


def _find_complex_echo_variables(echo_content: str) -> List[str]:
    """Find unusual percent-expansions in echo content."""
    complex_vars: List[str] = []
    variables: List[str] = re.findall(r"%([^%]+)%", echo_content)
    for var_content in variables:
        if " " in var_content or "\t" in var_content:
            continue
        var_name = re.match(r"^([A-Z0-9_~@#]+)", var_content, re.IGNORECASE)
        if var_name:
            continue
        if re.match(r"^~[a-z]*\d*$", var_content, re.IGNORECASE):
            continue
        complex_vars.append(var_content)
    return complex_vars


def _echo_has_unsafe_redirection(stripped: str) -> bool:
    """Return True when echo uses unsafe shell redirection."""
    has_safe_redirection = bool(
        re.search(
            r">\s*(nul|\"[^\"]*\"|[^\s&|<>]+)(\s*2>&1)?\s*$", stripped, re.IGNORECASE
        )
    )
    has_escaped_brackets = bool(re.search(r"\^[<>]", stripped))
    return (
        bool(re.search(r"[<>]", stripped))
        and not has_safe_redirection
        and not has_escaped_brackets
    )


def _check_echo_unicode_risk(stripped: str) -> bool:
    """Check for Unicode risks in echo commands."""
    echo_content = _extract_echo_content(stripped)
    if echo_content.strip() and not all(
        ord(c) < 128 for c in echo_content if c.strip()
    ):
        return True
    if _echo_has_unsafe_redirection(stripped):
        return True
    if _find_complex_echo_variables(echo_content):
        return True
    return bool(re.search(r"[\x00-\x1f\x7f-\xff]", echo_content))


def _check_search_unicode_risk(stripped: str) -> bool:
    """Check for Unicode risks in findstr/find commands."""
    if not all(ord(c) < 128 for c in stripped):
        return True
    if ">" in stripped or "<" in stripped:
        return True
    # Only flag switches known to affect Unicode handling (/u, /g, /p)
    return bool(re.search(r"(?:^|\s)/(?:u|g|p)(?:\s|$)", stripped, re.IGNORECASE))


def _check_general_unicode_risk(stripped: str) -> bool:
    """Check for general Unicode risks in other commands."""
    return not all(ord(c) < 128 for c in stripped) or bool(
        re.search(r"[\x00-\x1f\x7f-\xff]", stripped)  # Contains non-ASCII
    )


def _check_compatibility_warnings(  # pylint: disable=unused-argument
    line: str, line_num: int, stripped: str
) -> List[LintIssue]:
    """Check for compatibility-related warning issues."""
    issues: List[LintIssue] = []

    # W009: Windows version compatibility
    for cmd in OLDER_WINDOWS_COMMANDS:
        if re.match(rf"{cmd}\s", stripped, re.IGNORECASE):
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W009"],
                    context=f"Command '{cmd}' may not be available on older Windows versions",
                )
            )
            break

    # W010: Architecture-specific operation
    for pattern in ARCHITECTURE_SPECIFIC_PATTERNS:
        if pattern in stripped:
            issues.append(
                LintIssue(
                    line_number=line_num,
                    rule=RULES["W010"],
                    context=f"Architecture-specific reference: {pattern}",
                )
            )
            break

    # W011: Unicode handling issue - only flag when actually problematic
    unicode_issue = _check_unicode_handling_issue(stripped, line_num)
    if unicode_issue:
        issues.append(unicode_issue)

    # W027: Command behavior differs between interpreters
    interpreter_diff_commands = ["append", "dpath", "ftype", "assoc", "path"]
    parts = stripped.split()
    first_word = parts[0].lower() if parts else ""
    if first_word in interpreter_diff_commands:
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W027"],
                context=f"Command '{first_word}' behaves differently in COMMAND.COM vs cmd.exe",
            )
        )

    # W029: 16-bit command in 64-bit context
    # Only match .COM files being executed as commands, not domain names
    # Match patterns like: command.com, call something.com, start program.com
    # But not: ping google.com, http://site.com, etc.
    if re.search(
        r"^\s*(?:call\s+|start\s+)?[\w-]+\.com(?:\s|$)", stripped, re.IGNORECASE
    ):
        issues.append(
            LintIssue(
                line_number=line_num,
                rule=RULES["W029"],
                context="16-bit .COM file may not work in 64-bit Windows",
            )
        )

    return issues
